package main

import (
	"github.com/teddashh/AI-Intune/internal/totp"
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
	if token, msg = validateServiceTokenForm(req); msg != "" || token.Scope != "operate" {
		t.Fatal("Hermes must force operate scope")
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

func TestServiceTokenSelfAndRotationDenied(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	for _, scope := range []string{"view", "operate", "operator-admin"} {
		_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "agent-" + scope, Scope: scope, ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/jobs"}}, actor.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		mux := http.NewServeMux()
		mux.Handle("GET /v1/operator/service-tokens/self", http.NotFoundHandler())
		mux.Handle("POST /v1/operator/service-tokens/rotate", http.NotFoundHandler())
		boundary := newOperatorBoundary(mux, nil, st, operatorRoutePolicies, testOperatorAuthority)
		for _, method := range []string{"GET", "POST"} {
			path := "/v1/operator/service-tokens/self"
			if method == "POST" {
				path = "/v1/operator/service-tokens/rotate"
			}
			req := newBoundaryRequest(method, path, strings.NewReader("{}"))
			req.Header.Set("Authorization", "Bearer "+secret)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			boundary.ServeHTTP(rec, req)
			if method == "GET" && rec.Code != 200 {
				t.Fatal("self unavailable", rec.Code)
			}
			if method == "POST" && (rec.Code != 403 || !strings.Contains(rec.Body.String(), "SERVICE_TOKEN_ACTION_FORBIDDEN")) {
				t.Fatal("rotation must require a human", rec.Code)
			}
		}
	}
	tokens, err := st.ListServiceTokens()
	if err != nil || len(tokens) != 3 {
		t.Fatal("denied rotation created a token")
	}
}

func TestServiceTokenValidationPrecedesFactorsAndInternalFailureIsGeneric(t *testing.T) {
	mux, st, principal, agent := managementAuditFixture(t, false)
	actor := strings.TrimPrefix(principal.StableSubject(), "local-user:")
	factor, err := st.BeginTOTPEnrollment(actor)
	if err != nil {
		t.Fatal(err)
	}
	enroll, _ := totp.Code(factor, time.Now().Unix()/30-1)
	if _, err = st.ConfirmTOTP(actor, enroll); err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(factor, time.Now().Unix()/30)
	fields := url.Values{"name": {"bad name"}, "scope": {"view"}, "expiry_days": {"90"}, "routes": {"GET /v1/operator/jobs"}, "password": {usersPassword}, "code": {code}}
	good := managementAuditRequest(mux, principal, "create", fields, "192.0.2.1:1234", agent)
	fields.Set("password", "bad-password")
	fields.Set("code", "bad-code")
	bad := managementAuditRequest(mux, principal, "create", fields, "192.0.2.1:1234", agent)
	if good.Code != 400 || bad.Code != good.Code || bad.Body.String() != good.Body.String() || !strings.Contains(good.Body.String(), "Name invalid") {
		t.Fatal("validation depends on factors")
	}
	audits, err := st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range audits {
		if a.Action == store.AuditHubLoginFailed || a.Action == store.AuditMFAFailed {
			t.Fatal("invalid fields reached factor verification")
		}
	}
	fields = url.Values{"id": {"00000000-0000-4000-8000-000000000001"}, "password": {"bad-password"}, "code": {"bad-code"}}
	bad = managementAuditRequest(mux, principal, "revoke", fields, "192.0.2.2:1234", agent)
	fields.Set("password", usersPassword)
	fields.Set("code", code)
	good = managementAuditRequest(mux, principal, "revoke", fields, "192.0.2.2:1234", agent)
	if good.Code != 400 || good.Code != bad.Code || good.Body.String() != bad.Body.String() || !strings.Contains(good.Body.String(), "Password or code incorrect.") {
		t.Fatal("post-factor failure reveals factor validity")
	}
	audits, err = st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range audits {
		if a.Action == store.AuditMFAFailed {
			t.Fatal("test did not reach post-factor failure")
		}
	}
}
