package main

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/web"
)

func TestScheduleWebBoundaryAuthCSRF(t *testing.T) {
	st := boundaryStore(t)
	ui, err := web.New(st, "")
	if err != nil {
		t.Fatal(err)
	}
	auth := &boundaryAuthorizer{allow: true}
	handler, err := newHubHTTPHandler(&hub{store: st}, ui, auth, testOperatorAuthority)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tenant/schedules/preview", "/tenant/schedules/apply", "/tenant/schedules/example/run-now"} {
		req := newBoundaryRequest("POST", path, strings.NewReader("id=example"))
		req.RemoteAddr = "100.100.10.20:4321"
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != 403 || !strings.Contains(w.Body.String(), "跨來源") {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	auth.allow = false
	req := newBoundaryRequest("GET", "/tenant/schedules", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatal(w.Code)
	}
}
func TestScheduleWebBoundaryWritePermission(t *testing.T) {
	for _, body := range []string{"script_id=bat-sweep-report-v1", "request=%7B%22script_id%22%3A%22bat-sweep-report-v1%22%7D"} {
		r := httptest.NewRequest("POST", "/tenant/schedules/preview", strings.NewReader(body))
		if got := scheduleWebPermission(r, nil); got != operatorauth.Admin {
			t.Fatal(got)
		}
	}
	r := httptest.NewRequest("POST", "/tenant/schedules/preview", strings.NewReader("script_id=fleet-probe-v1"))
	if got := scheduleWebPermission(r, nil); got != operatorauth.Operate {
		t.Fatal(got)
	}
}

func TestScheduleWebUsesScriptMutationLimiter(t *testing.T) {
	st := boundaryStore(t)
	ui, err := web.New(st, "")
	if err != nil {
		t.Fatal(err)
	}
	h := &hub{store: st}
	auth := &boundaryAuthorizer{allow: true}
	handler, err := newHubHTTPHandler(h, ui, auth, testOperatorAuthority)
	if err != nil {
		t.Fatal(err)
	}
	principal := boundaryPrincipal(operatorauth.Operate)
	for i := 0; i < scriptRunSubjectBurst; i++ {
		if !h.scriptRunLimiter.allow(principal.StableSubject(), time.Now()) {
			t.Fatal("limiter setup")
		}
	}
	req := newBoundaryRequest("POST", "/tenant/schedules/preview", strings.NewReader("expected_revision=0"))
	req.RemoteAddr = "100.100.10.20:4321"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != 429 || w.Header().Get("Retry-After") == "" {
		t.Fatal(w.Code, w.Body.String())
	}
}
