package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/totp"
)

func TestServiceTokenRouteEditWeb(t *testing.T) {
	h, st := localAccountHandler(t)
	actor, err := st.CreateFirstAdmin("alice", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	factor, err := st.BeginTOTPEnrollment(actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	enroll, _ := totp.Code(factor, time.Now().Unix()/30-1)
	if _, err := st.ConfirmTOTP(actor.AccountID, enroll); err != nil {
		t.Fatal(err)
	}
	cookie := adminSession(t, st)
	token, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "reader", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/machines"}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	page := accountRequest(h, "GET", "/account/service-tokens", "", cookie)
	if page.Code != 200 || !strings.Contains(page.Body.String(), `action="/account/service-tokens/routes"`) || !strings.Contains(page.Body.String(), `value="GET /v1/operator/machines" checked`) {
		t.Fatal("missing selected route editor")
	}
	code, _ := totp.Code(factor, time.Now().Unix()/30)
	fields := url.Values{"id": {token.ID}, "routes": {"GET /v1/operator/jobs"}, "password": {usersPassword}, "code": {code}}
	// Browser cross-origin requests are rejected before factor verification.
	req := httptest.NewRequest("POST", "https://hub.example.com/account/service-tokens/routes", strings.NewReader(fields.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://other.example")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-origin edit status %d", rec.Code)
	}
	fields.Set("code", "invalid")
	if w := accountRequest(h, "POST", "/account/service-tokens/routes", fields.Encode(), cookie); w.Code != 400 {
		t.Fatalf("missing fresh factor accepted: %d", w.Code)
	}
	fields.Set("code", code)
	w := accountRequest(h, "POST", "/account/service-tokens/routes", fields.Encode(), cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Allowed routes updated immediately.") {
		t.Fatalf("edit failed: %d", w.Code)
	}
	if _, err := st.AuthenticateServiceToken(secret, "GET /v1/operator/jobs", "192.0.2.1", "view"); err != nil {
		t.Fatal("new route not effective")
	}
	if _, err := st.AuthenticateServiceToken(secret, "GET /v1/operator/machines", "192.0.2.1", "view"); err == nil {
		t.Fatal("old route still effective")
	}
	// TOTP codes cannot be replayed for another sensitive edit.
	if w := accountRequest(h, "POST", "/account/service-tokens/routes", fields.Encode(), cookie); w.Code != 400 {
		t.Fatal("factor replay accepted")
	}
}

func TestServiceTokenEditRoutesUsesManifest(t *testing.T) {
	for _, routes := range [][]string{nil, {"GET /v1/operator/not-a-route"}, {"POST /v1/operator/service-tokens/rotate"}, {"GET /v1/operator/machines", "GET /v1/operator/machines"}} {
		if validServiceTokenEditRoutes(routes) {
			t.Fatalf("accepted %v", routes)
		}
	}
	if !validServiceTokenEditRoutes([]string{"GET /v1/operator/jobs"}) {
		t.Fatal("manifest route rejected")
	}
}
