package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
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
