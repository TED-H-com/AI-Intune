package web

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestSigninsWebAdminMFAAndCSRF(t *testing.T) {
	s, st := newServer(t)
	now := time.Now().UTC()
	if e := st.UpsertMachine(store.Machine{MachineID: "fixture", DisplayName: "Example host", OS: "linux", CreatedAt: now}); e != nil {
		t.Fatal(e)
	}
	if e := st.RecordSigninHealth("fixture", []model.AuthHealth{{CLI: "agy", Slot: 1, Account: "person@example.com", Status: "logged_out"}}, now); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	s.signinRoutes(mux)
	request := func(method, path string, form url.Values, p operatorauth.Principal, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		r = operatorauth.WithPrincipal(r, p)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache enabled")
		}
		return w
	}
	viewer := diskWebPrincipal(false, false, "")
	admin := diskWebPrincipal(true, true, "fixture")
	admin.MFAVerifiedAt = time.Now()
	form := url.Values{"target": {"fixture:agy:1"}}
	if w := request("GET", "/signins", nil, viewer, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "Example host") || strings.Contains(w.Body.String(), "<button>Sign in") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("POST", "/signins/start", form, viewer, "http://example.com"); w.Code != 403 {
		t.Fatal("viewer start", w.Code)
	}
	stale := admin
	stale.MFAVerifiedAt = time.Now().Add(-time.Hour)
	if w := request("POST", "/signins/start", form, stale, "http://example.com"); w.Code != 403 {
		t.Fatal("stale MFA", w.Code)
	}
	if w := request("POST", "/signins/start", form, admin, ""); w.Code != 403 {
		t.Fatal("missing CSRF evidence", w.Code)
	}
	if w := request("POST", "/signins/start", form, admin, "https://evil.example"); w.Code != 403 {
		t.Fatal("cross-origin", w.Code)
	}
	if w := request("POST", "/signins/start", form, admin, "http://example.com"); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	sessions, e := st.SigninSessions()
	if e != nil || len(sessions) != 1 {
		t.Fatal(e, sessions)
	}
	id := sessions[0].ID
	st.SigninCommands("fixture")
	if e = st.UpdateSignin("fixture", model.SigninUpdate{ID: id, State: "waiting_for_code", URL: "https://accounts.google.com/o/oauth2/auth?fixture=1"}); e != nil {
		t.Fatal(e)
	}
	if w := request("GET", "/signins", nil, admin, ""); w.Code != 200 || !strings.Contains(w.Body.String(), "rel=\"noopener noreferrer\"") || !strings.Contains(w.Body.String(), "Paste the code") || w.Header().Get("Refresh") != "" || !strings.Contains(w.Body.String(), "<script>"+SigninRefreshScript+"</script>") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request("GET", "/v1/operator/signins", nil, viewer, ""); w.Code != 200 || strings.Contains(w.Body.String(), "https://") || strings.Contains(w.Body.String(), id) {
		t.Fatal("API leaked session data", w.Body.String())
	}
	for _, op := range []string{"code", "cancel"} {
		f := url.Values{"signin_code": {"synthetic-paste-code"}}
		if op == "cancel" {
			f = nil
		}
		path := "/signins/" + id + "/" + op
		for _, p := range []operatorauth.Principal{viewer, stale} {
			if w := request("POST", path, f, p, "http://example.com"); w.Code != 403 {
				t.Fatal(op, w.Code)
			}
		}
		if w := request("POST", path, f, admin, "http://example.com"); w.Code != 303 {
			t.Fatal(op, w.Code, w.Body.String())
		}
	}
}

type fakeSigninProvider struct{ sent []channels.Message }

func (p *fakeSigninProvider) Name() string { return "example" }
func (p *fakeSigninProvider) Kind() string { return "webhook" }
func (p *fakeSigninProvider) Health(context.Context) (channels.HealthStatus, error) {
	return channels.Ready, nil
}
func (p *fakeSigninProvider) Send(_ context.Context, m channels.Message) error {
	p.sent = append(p.sent, m)
	return nil
}
func TestSigninNotificationUsesProviderAndSafeText(t *testing.T) {
	s, _ := newServer(t)
	s.hubBase = "https://hub.example.com"
	p := &fakeSigninProvider{}
	s.sendSigninNotification(context.Background(), p, store.SigninNotification{DisplayName: "Example host", CLI: "codex", Account: "person@example.com"})
	if len(p.sent) != 1 || !strings.Contains(p.sent[0].Text, "https://hub.example.com/signins") || !strings.Contains(p.sent[0].Text, "Example host") {
		t.Fatal(p.sent)
	}
}

func TestSigninsBulkOnlyTargetsAccountsNeedingSignIn(t *testing.T) {
	s, st := newServer(t)
	now := time.Now().UTC()
	for id, status := range map[string]string{"missing": "logged_out", "soon": "expiring", "unknown": "unknown", "healthy": "ok"} {
		if err := st.UpsertMachine(store.Machine{MachineID: id, DisplayName: "Example " + id, OS: "linux", CreatedAt: now}); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordSigninHealth(id, []model.AuthHealth{{CLI: "codex", Slot: 1, Account: "person@example.com", Status: status}}, now); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest("GET", "/signins", nil)
	r = operatorauth.WithPrincipal(r, diskWebPrincipal(true, true, "fixture"))
	w := httptest.NewRecorder()
	s.signinsPage(w, r)
	body := w.Body.String()
	start := strings.Index(body, `<form method="post" action="/signins/start">`)
	if start < 0 {
		t.Fatal("bulk form missing")
	}
	end := strings.Index(body[start:], "</form>")
	if end < 0 {
		t.Fatal("bulk form incomplete")
	}
	bulk := body[start : start+end]
	if !strings.Contains(bulk, "Sign in all") || !strings.Contains(bulk, "missing:codex:1") || !strings.Contains(bulk, "soon:codex:1") || strings.Contains(bulk, "unknown:codex:1") || strings.Contains(bulk, "healthy:codex:1") {
		t.Fatal("bulk form targets the wrong accounts", bulk)
	}
}
