package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/store"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/secrets"
)

type secretFailureProvider struct{}

func (secretFailureProvider) List(context.Context, string) ([]secrets.Reference, error) {
	return []secrets.Reference{{Name: "unavailable", Ref: "bws://project/key"}}, nil
}
func (secretFailureProvider) Get(context.Context, string) (secrets.Secret, error) {
	return secrets.NewSecret("sentinel-secret-web"), errors.New("sentinel-secret-web")
}
func (secretFailureProvider) Health(context.Context) error { return errors.New("sentinel-secret-web") }
func TestSecretsStatusAuthorizationAndRedaction(t *testing.T) {
	s, _ := newServer(t)
	names, err := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("WEB_SECRET_TEST", "sentinel-secret-web")
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	mux := http.NewServeMux()
	s.Routes(mux)
	for _, provider := range []secrets.SecretProvider{secrets.New([]secrets.Reference{{Name: "test", Ref: "env://WEB_SECRET_TEST"}, {Name: "missing", Ref: "env://WEB_SECRET_MISSING"}}), secretFailureProvider{}} {
		s.SetSecretProvider(provider)
		for _, path := range []string{"/secrets", "/v1/operator/secrets"} {
			for _, admin := range []bool{false, true} {
				granted := operatorauth.CapabilityNames{View: names.View}
				want := http.StatusForbidden
				if admin {
					granted.Admin = names.Admin
					want = http.StatusOK
				}
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, requestWithCapabilities(http.MethodGet, path, granted))
				if rec.Code != want {
					t.Fatalf("%s got %d want %d", path, rec.Code, want)
				}
				if strings.Contains(rec.Body.String(), "sentinel-secret-web") {
					t.Fatal("secret in response")
				}
				if admin && !strings.Contains(rec.Body.String(), "status") && !strings.Contains(rec.Body.String(), "Status") {
					t.Fatal("missing status")
				}
				if admin && path == "/v1/operator/secrets" {
					var rows []secretStatus
					if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
						t.Fatal(err)
					}
					if len(rows) == 2 && (rows[0].Status != "present" || rows[1].Status != "missing") {
						t.Fatal("incorrect local status")
					}
					if len(rows) == 1 && rows[0].Status != "error" {
						t.Fatal("incorrect error status")
					}
				}
				if rec.Header().Get("Cache-Control") != "no-store" {
					t.Fatal("cache allowed")
				}
			}
		}
	}
	if strings.Contains(logs.String(), "sentinel-secret-web") {
		t.Fatal("secret in logs")
	}
}

func TestSecretFetchAdminCSRFAndAudit(t *testing.T) {
	s, st := newServer(t)
	names, _ := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	mux := http.NewServeMux()
	s.Routes(mux)
	spy := &secretFetchSpy{}
	s.SetSecretProvider(spy)
	request := func(ref string, admin bool, site string) *httptest.ResponseRecorder {
		caps := operatorauth.CapabilityNames{View: names.View}
		if admin {
			caps.Admin = names.Admin
		}
		req := requestWithCapabilities("POST", "/secrets/test", caps)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		req.Body = io.NopCloser(strings.NewReader(url.Values{"ref": {ref}}.Encode()))
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}
	for _, tc := range []struct {
		admin     bool
		site, ref string
		code      int
	}{
		{false, "same-origin", "bws://project/key", 403},
		{true, "", "bws://project/key", 403},
		{true, "cross-site", "bws://project/key", 403},
		{true, "same-origin", "env://ARBITRARY", 404},
		{true, "same-origin", "bws://project/key", 200},
	} {
		rec := request(tc.ref, tc.admin, tc.site)
		if rec.Code != tc.code {
			t.Fatalf("got %d want %d", rec.Code, tc.code)
		}
		if strings.Contains(rec.Body.String(), "sentinel-secret-web") {
			t.Fatal("value leaked")
		}
	}
	audits, e := st.Audit("", 100)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for _, a := range audits {
		if a.Action == store.AuditSecretTest {
			count++
			if strings.Contains(fmt.Sprint(a), "sentinel-secret-web") {
				t.Fatal("audit leaked")
			}
			if a.Subject != "bws://project/key" || a.At.IsZero() {
				t.Fatal("audit metadata missing")
			}
		}
	}
	if spy.calls != 1 {
		t.Fatal("unexpected provider invocations")
	}
	if count != 2 {
		t.Fatal("intent/outcome not audited")
	}
	if _, e := st.DB().Exec("CREATE TRIGGER secret_test_failure BEFORE INSERT ON audit_log WHEN NEW.action='secret-test' BEGIN SELECT RAISE(ABORT,'unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	rec := request("bws://project/key", true, "same-origin")
	if rec.Code != 500 {
		t.Fatal("audit failure did not fail closed")
	}
	if spy.calls != 1 {
		t.Fatal("fetched without audit")
	}
}

// A failed intent audit must prevent even a provider invocation.
type secretFetchSpy struct {
	secretFailureProvider
	calls int
}

func (p *secretFetchSpy) Get(ctx context.Context, ref string) (secrets.Secret, error) {
	p.calls++
	return p.secretFailureProvider.Get(ctx, ref)
}
