package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestOperatorStaleMachinesReadContract(t *testing.T) {
	f := observedOperatorFixture(t)
	now := time.Now().UTC()
	for _, id := range []string{"expired", "live"} {
		if _, err := f.store.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,?,?)`, id, id, now.Add(-25*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		expires := now.Add(time.Hour)
		if id == "expired" {
			expires = now.Add(-time.Hour)
		}
		if _, err := f.store.DB().Exec(`INSERT INTO enrollment_tokens(token_hash,display_name,used_by,created_at,expires_at) VALUES(?,?,?,?,?)`, id, id, id, now.Format(time.RFC3339), expires.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	request := func(path string, view bool) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", path, nil)
		if view {
			req = operatorauth.WithPrincipal(req, operatorauth.Principal{GrantedCapabilities: operatorauth.CapabilityNames{View: "view"}})
		}
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		return rec
	}
	route := "/v1/operator/stale-machines"
	denied := request(route, false)
	if denied.Code != 403 || strings.Contains(denied.Body.String(), `"machine_id"`) {
		t.Fatalf("unauthorized %d %s", denied.Code, denied.Body.String())
	}
	for _, suffix := range []string{"?", "?limit=1", "?limit=1&limit=2", "?%zz", "?cursor=", "?cursor=bad", "?cursor=bad&cursor=bad", "?cursor=" + strings.Repeat("a", 7000)} {
		if got := request(route+suffix, true); got.Code != 400 {
			t.Fatalf("invalid query %q: %d", suffix, got.Code)
		}
	}
	got := request(route, true)
	var result operator.StaleMachineReview
	if got.Code != 200 || got.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(got.Body.Bytes(), &result) != nil || len(result.Items) != 1 || result.Items[0].MachineID != "expired" {
		t.Fatalf("read %d %s", got.Code, got.Body.String())
	}
	for _, term := range []string{"token_hash", "agent_token", "used_by", `"live"`} {
		if strings.Contains(got.Body.String(), term) {
			t.Fatalf("unexpected evidence %q", term)
		}
	}
	revision := int64(0)
	svc := operator.New(f.store)
	preview, err := svc.PreviewMachineLifecycle(operator.MachineLifecyclePreviewRequest{MachineID: "expired", DesiredState: operator.MachineLifecycleStateRetired, ExpectedRevision: &revision})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ChangeMachineLifecycle(operator.MachineLifecycleRequest{MachineID: "expired", DesiredState: operator.MachineLifecycleStateRetired, ExpectedRevision: &revision, ConfirmDisplayName: "expired", PreviewDigest: preview.PreviewDigest, Reason: "reviewed", IdempotencyKey: "stale-api-retire"})
	if err != nil {
		t.Fatal(err)
	}
	after := request(route, true)
	if after.Code != 200 || !strings.Contains(after.Body.String(), `"items":[]`) {
		t.Fatalf("after retirement %s", after.Body.String())
	}
	policy, ok := operatorRoutePolicies["GET "+route]
	if !ok || policy.Permission != operatorauth.View || policy.Representation != operatorJSON || policy.ServiceTokenEligible != serviceEligible {
		t.Fatalf("route policy %+v", policy)
	}
	// Exercise the actual boundary, including rejection of machine bearer auth.
	mux := http.NewServeMux()
	mux.Handle("GET "+route, f.mux)
	boundary := newOperatorBoundary(mux, &boundaryAuthorizer{}, f.store, map[string]operatorRoutePolicy{"GET " + route: policy}, testOperatorAuthority)
	req := newBoundaryRequest(http.MethodGet, route, nil)
	req.Header.Set("Authorization", "Bearer machine-credential")
	rec := httptest.NewRecorder()
	boundary.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), `"items"`) {
		t.Fatalf("machine bearer read %d", rec.Code)
	}
}

func TestOperatorStaleMachinesServiceTokenAllowlist(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("review-admin", "a sufficiently long test password")
	if err != nil {
		t.Fatal(err)
	}
	route := "GET /v1/operator/stale-machines"
	mux := http.NewServeMux()
	h := &hub{store: st}
	h.operatorRoutes(mux)
	boundary := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{route: operatorRoutePolicies[route]}, testOperatorAuthority)
	for _, allowed := range []bool{false, true} {
		routes := []string{"GET /v1/operator/machines"}
		name := "roster-only"
		if allowed {
			routes = []string{route}
			name = "review-reader"
		}
		_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: name, Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: routes}, actor.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		req := newBoundaryRequest("GET", "/v1/operator/stale-machines", nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		boundary.ServeHTTP(rec, req)
		if allowed {
			if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"items":[]`) {
				t.Fatalf("authorized read %d", rec.Code)
			}
		} else if rec.Code != 401 || strings.Contains(rec.Body.String(), `"items"`) {
			t.Fatalf("route allowlist bypass %d", rec.Code)
		}
	}
}

func TestOperatorStaleMachinesPagination(t *testing.T) {
	f := observedOperatorFixture(t)
	stamp := time.Now().UTC().Add(-25 * time.Hour).Format(time.RFC3339)
	for i := 0; i < 102; i++ {
		id := fmt.Sprintf("api-page-%03d", i)
		if _, err := f.store.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,?,?)`, id, id, stamp); err != nil {
			t.Fatal(err)
		}
	}
	cursor := ""
	count := 0
	for {
		path := "/v1/operator/stale-machines"
		if cursor != "" {
			path += "?cursor=" + cursor
		}
		req := httptest.NewRequest("GET", path, nil)
		req = operatorauth.WithPrincipal(req, operatorauth.Principal{GrantedCapabilities: operatorauth.CapabilityNames{View: "view"}})
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		var page operator.StaleMachineReview
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &page) != nil {
			t.Fatalf("page %d %s", rec.Code, rec.Body.String())
		}
		for _, item := range page.Items {
			if item.MachineID != fmt.Sprintf("api-page-%03d", count) {
				t.Fatalf("skip/duplicate: %s", item.MachineID)
			}
			count++
		}
		if page.NextCursor == nil {
			break
		}
		cursor = *page.NextCursor
	}
	if count != 102 {
		t.Fatalf("read %d candidates", count)
	}
}
