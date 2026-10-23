package web

import (
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHostProfileHumanAndReadAPI(t *testing.T) {
	s, st := newServer(t)
	mux := http.NewServeMux()
	s.hostProfileRoutes(mux)
	req := func(method, path string, v url.Values, admin bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = operatorauth.WithPrincipal(r, diskWebPrincipal(admin, false, ""))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	w := req("GET", "/machines/host-profile", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Keep running with the lid closed") || !strings.Contains(w.Body.String(), "Read-only") {
		t.Fatal(w.Code, w.Body.String())
	}
	v := url.Values{"lid_ignore": {"true"}, "journald_max_mb": {"500"}}
	if w = req("POST", "/machines/host-profile", v, false); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w = req("POST", "/machines/host-profile", v, true); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	p, _ := st.HostProfile()
	if p.LidIgnore == nil || !*p.LidIgnore || p.DisableSleep != nil {
		t.Fatal(p)
	}
	w = req("GET", "/v1/operator/host-profile", nil, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"lid_ignore":true`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, v := range []url.Values{{"unknown": {"true"}}, {"lid_ignore": {"true", "false"}}, {"journald_max_mb": {"1"}}, {"power_profile": {"shell"}}} {
		if w = req("POST", "/machines/host-profile", v, true); w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
