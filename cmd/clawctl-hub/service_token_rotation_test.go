package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestServiceTokenFormFieldsAndErrors(t *testing.T) {
	fields := url.Values{"name": {"hermes"}, "scope": {"operate"}, "expiry_days": {"90"}, "routes": {"GET /v1/operator/jobs"}}
	tests := []struct{ key, value, want string }{
		{"name", "bad name", "Name invalid"},
		{"scope", "admin", "Scope invalid"},
		{"expiry_days", "99", "Expiry preset invalid"},
		{"routes", "", "not eligible"},
		{"routes", "GET /v1/operator/no-such-route", "not eligible"},
		{"source_cidrs", "192.0.2.999/24", "CIDR 192.0.2.999/24 invalid"},
		{"max_lifetime", "100", "Maximum lifetime invalid"},
	}
	for _, tc := range tests {
		t.Run(tc.key+"/"+tc.value, func(t *testing.T) {
			copy := url.Values{}
			for k, v := range fields {
				copy[k] = append([]string(nil), v...)
			}
			copy.Set(tc.key, tc.value)
			req := httptest.NewRequest("POST", "/", strings.NewReader(copy.Encode()))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.ParseForm()
			_, message := validateServiceTokenForm(req)
			if !strings.Contains(message, tc.want) {
				t.Fatal(message)
			}
		})
	}
	req := httptest.NewRequest("POST", "/", nil)
	req.PostForm = fields
	delete(fields, "routes")
	if _, msg := validateServiceTokenForm(req); msg != "No routes selected." {
		t.Fatal(msg)
	}
	fields.Set("preset", "hermes-default")
	token, msg := validateServiceTokenForm(req)
	if msg != "" || len(token.Allowlist) != len(hermesServiceRoutes) {
		t.Fatal(msg)
	}
	fields.Set("scope", "view")
	if _, msg = validateServiceTokenForm(req); msg != "Script-runs requires operate scope." {
		t.Fatal(msg)
	}
	mux, _, principal, _ := managementAuditFixture(t, true)
	get := httptest.NewRequest("GET", "/account/service-tokens", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, operatorauth.WithPrincipal(get, principal))
	for _, label := range []string{"Name</label>", "Scope</label>", "Expiry</label>", "Allowed routes", "Optional source CIDRs", "Current password", "Authenticator code", "hermes-default", `pattern="[a-zA-Z0-9_-]{1,64}"`} {
		if !strings.Contains(rec.Body.String(), label) {
			t.Error("missing", label)
		}
	}
}

func TestServiceTokenSelfAndRotateHTTP(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	old, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "hermes", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/jobs"}, SourceCIDRs: []string{"192.0.2.0/24"}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	for _, route := range []string{"GET /v1/operator/service-tokens/self", "POST /v1/operator/service-tokens/rotate"} {
		mux.Handle(route, http.NotFoundHandler())
	}
	boundary := newOperatorBoundary(mux, nil, st, operatorRoutePolicies, testOperatorAuthority)
	call := func(method, path, credential, ip string) *httptest.ResponseRecorder {
		req := newBoundaryRequest(method, path, strings.NewReader("{}"))
		req.RemoteAddr = ip + ":1234"
		req.Header.Set("Content-Type", "application/json")
		if credential != "" {
			req.Header.Set("Authorization", "Bearer "+credential)
		}
		rec := httptest.NewRecorder()
		boundary.ServeHTTP(rec, req)
		return rec
	}
	self := call("GET", "/v1/operator/service-tokens/self", secret, "192.0.2.1")
	if self.Code != 200 || !strings.Contains(self.Body.String(), old.ID) || strings.Contains(self.Body.String(), secret) {
		t.Fatal("self response", self.Code)
	}
	if rec := call("POST", "/v1/operator/service-tokens/rotate", secret, "198.51.100.1"); rec.Code != 401 {
		t.Fatal("CIDR", rec.Code)
	}
	rotated := call("POST", "/v1/operator/service-tokens/rotate", secret, "192.0.2.1")
	if rotated.Code != 200 || rotated.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("rotate", rotated.Code, rotated.Body.String())
	}
	var result struct {
		Token string `json:"token"`
	}
	if err = json.Unmarshal(rotated.Body.Bytes(), &result); err != nil || !store.ValidServiceSecret(result.Token) {
		t.Fatal("rotation response")
	}
	if rec := call("POST", "/v1/operator/service-tokens/rotate", secret, "192.0.2.1"); rec.Code != 409 {
		t.Fatal("double rotate", rec.Code)
	}
	if rec := call("GET", "/v1/operator/service-tokens/self", "", "192.0.2.1"); rec.Code != 401 {
		t.Fatal("no bearer", rec.Code)
	}
	if err = st.RevokeServiceToken(old.ID, actor.AccountID); err != nil {
		t.Fatal(err)
	}
	if rec := call("GET", "/v1/operator/service-tokens/self", result.Token, "192.0.2.1"); rec.Code != 401 {
		t.Fatal("chain revoke", rec.Code)
	}
}
