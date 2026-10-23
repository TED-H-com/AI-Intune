package main

import (
	"net/http"
	"strings"
	"testing"
)

func TestOperatorMachineSafeEndpoint(t *testing.T) {
	f := observedOperatorFixture(t)
	path := "/v1/operator/machines/" + f.machine.id + "/safe"
	for _, tc := range []struct {
		path   string
		status int
	}{{path, 200}, {path + "?limit=1", 400}, {"/v1/operator/machines/missing/safe", 404}} {
		r := operatorRequest(t, f.mux, http.MethodGet, tc.path, "", "")
		if r.Code != tc.status || r.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("status=%d", r.Code)
		}
		if tc.status == 200 && (!strings.Contains(r.Body.String(), `"redactions"`) || !strings.Contains(r.Body.String(), `"redaction_flags"`) || !strings.Contains(r.Body.String(), `"evidence"`)) {
			t.Fatal("missing safe projection")
		}
	}
	policy := operatorRoutePolicies["GET /v1/operator/machines/{id}/safe"]
	if !policy.ServiceTokenEligible.eligible() {
		t.Fatal("safe route unavailable")
	}
	for _, route := range hermesServiceRoutes {
		if route == "GET /v1/operator/machines/{id}/safe" {
			t.Fatal("safe route included in default")
		}
	}
}
