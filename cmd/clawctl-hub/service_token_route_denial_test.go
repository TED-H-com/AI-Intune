package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatoragent"
	"github.com/teddashh/AI-Intune/internal/store"
)

// A valid token on a route outside its allowlist gets 403 naming the layer,
// and never spends the brute-force budget; a bad token stays a generic 401.
func TestServiceTokenRouteNotAllowlisted(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	allow := []string{"GET /v1/operator/machines"}
	_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "reader", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: allow}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	for _, route := range []string{"GET /v1/operator/machines", "GET /v1/operator/jobs"} {
		mux.HandleFunc(route, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })
	}
	mux.HandleFunc("GET /v1/operator/service-tokens/self", http.NotFoundHandler().ServeHTTP)
	b := newOperatorBoundary(mux, nil, st, operatorRoutePolicies, testOperatorAuthority)
	b.serviceAttempts = newIPLimiter(1, 2) // two failures allowed
	do := func(path, auth string) *httptest.ResponseRecorder {
		req := newBoundaryRequest("GET", path, nil)
		req.Header.Set("Authorization", "Bearer "+auth)
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		return rec
	}
	for i := 0; i < 5; i++ {
		rec := do("/v1/operator/jobs", secret)
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		if rec.Code != 403 || body.Code != "ROUTE_NOT_ALLOWLISTED" {
			t.Fatalf("denied route: %d %s", rec.Code, rec.Body.String())
		}
	}
	if rec := do("/v1/operator/machines", secret); rec.Code != 204 {
		t.Fatalf("route denials spent the failure budget: %d", rec.Code)
	}
	bad := secret[:len(secret)-1] + "A"
	if bad == secret {
		bad = secret[:len(secret)-1] + "B"
	}
	if rec := do("/v1/operator/jobs", bad); rec.Code != 401 {
		t.Fatalf("bad token: %d", rec.Code)
	}
	rec := do("/v1/operator/service-tokens/self", secret)
	var self struct {
		Allowlist []string `json:"allowlist"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &self) != nil || len(self.Allowlist) != 1 || self.Allowlist[0] != allow[0] {
		t.Fatalf("self: %d %s", rec.Code, rec.Body.String())
	}
}

// Every MCP tool declares its Hub routes, and each one is a registered Hub
// route, so tools/list filtering cannot drift from the Hub. Tools whose routes
// a service token can never hold are simply never listed for a token.
func TestOperatorToolRoutesAreRegistered(t *testing.T) {
	for _, tool := range operatoragent.Tools() {
		routes := operatoragent.ToolRoutes(tool.Name)
		if len(routes) == 0 {
			t.Errorf("%s declares no routes", tool.Name)
		}
		for _, route := range routes {
			if _, ok := operatorRoutePolicies[route]; !ok {
				t.Errorf("%s: %s is not a registered Hub route", tool.Name, route)
			}
		}
	}
}
