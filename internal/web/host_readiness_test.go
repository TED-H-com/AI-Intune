package web

import (
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestReadinessHumanAndAPI(t *testing.T) {
	s, st := newServer(t)
	mux := http.NewServeMux()
	s.readinessRoutes(mux)
	req := func(method, path string, v url.Values, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = operatorauth.WithPrincipal(r, diskWebPrincipal(admin, false, ""))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w := req("GET", "/readiness", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Enroll the first machine") {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := st.UpsertMachine(store.Machine{MachineID: "example", DisplayName: "Example", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	v := url.Values{"machine": {"example"}, "path": {"tailscale"}, "sudoers_path": {"/etc/sudoers.d/agent-scoped"}, "backup_unit": {"backup.service"}}
	if w = req("POST", "/readiness", v, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w = req("POST", "/readiness", v, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = req("GET", "/readiness?machine=example", nil, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Save readiness targets") || !strings.Contains(w.Body.String(), "Unknown") {
		t.Fatal(w.Code, w.Body.String())
	}
	w = req("GET", "/v1/operator/machines/example/readiness", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"path":"tailscale"`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = req("GET", "/v1/operator/machines/missing/readiness", nil, false); w.Code != 404 {
		t.Fatal(w.Code)
	}
}

func TestFleetReadinessFormAndGroups(t *testing.T) {
	s, st := newServer(t)
	mux := http.NewServeMux()
	s.readinessRoutes(mux)
	request := func(method string, v url.Values, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/readiness", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = operatorauth.WithPrincipal(r, diskWebPrincipal(admin, false, ""))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	v := url.Values{"scope": {"fleet"}, "path": {"tailscale"}, "expected_clis": {"agy", "codex"}, "expected_user_units": {"worker.timer\nbackup.service"}, "auto_remediate": {"on"}}
	if w := request("POST", v, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request("POST", v, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	profile, err := st.FleetReadinessProfile()
	if err != nil || len(profile.ExpectedCLIs) != 2 || !profile.AutoRemediateUserUnits {
		t.Fatal(profile, err)
	}
	for _, m := range []store.Machine{{MachineID: "opaque-a", DisplayName: "Alpha"}, {MachineID: "opaque-b", DisplayName: "Beta"}} {
		m.CreatedAt = time.Now().UTC()
		if err := st.UpsertMachine(m); err != nil {
			t.Fatal(err)
		}
	}
	w := request("GET", nil, false)
	body := w.Body.String()
	for _, want := range []string{"Needs you (2)", "Fixing itself (16)", "Fleet defaults", "Alpha", "Beta", "/readiness?machine=opaque-a#readiness"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(body, ">opaque-a<") || strings.Contains(body, "Save fleet defaults") {
		t.Fatal("viewer labels or controls")
	}
	v.Set("expected_user_units", "../bad.service")
	if w := request("POST", v, true); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
