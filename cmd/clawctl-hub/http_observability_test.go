package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/web"
)

func TestRequestDurationLoggingPattern(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /machines/{id}", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) })
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	handler := newLoggingMiddleware(1000, nil)(mux)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/machines/private-machine-id?token=private-query", nil))
	output := buf.String()
	for _, want := range []string{`"method":"GET"`, `"route":"GET /machines/{id}"`, `"status":201`, `"duration_ms":`} {
		if !strings.Contains(output, want) {
			t.Fatalf("missing %q: %s", want, output)
		}
	}
	if strings.Contains(output, "private") {
		t.Fatal(output)
	}
}

func TestPprofAdminOnly(t *testing.T) {
	for _, tc := range []struct {
		name           string
		enabled, admin bool
		status         int
	}{
		{"disabled", false, true, 404}, {"non-admin", true, false, 403}, {"admin", true, true, 200},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := boundaryStore(t)
			ui, err := web.New(st, "hub")
			if err != nil {
				t.Fatal(err)
			}
			auth := &boundaryAuthorizer{allow: tc.admin}
			handler, err := newHubHTTPHandler(&hub{store: st, pprofEnabled: tc.enabled}, ui, auth, testOperatorAuthority)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/debug/pprof/", "/debug/pprof/goroutine?debug=1"} {
				rec := httptest.NewRecorder()
				req := newBoundaryRequest("GET", path, nil)
				req.RemoteAddr = "100.100.10.20:4321"
				handler.ServeHTTP(rec, req)
				if rec.Code != tc.status {
					t.Fatalf("%s status=%d want=%d body=%s", path, rec.Code, tc.status, rec.Body.String())
				}
			}
			if tc.enabled {
				for _, permission := range auth.snapshotCalls() {
					if permission != operatorauth.Admin {
						t.Fatalf("permission=%v", permission)
					}
				}
			}
		})
	}
}
