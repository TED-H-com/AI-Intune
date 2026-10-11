package main

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/clientip"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/totp"
	"github.com/teddashh/AI-Intune/internal/web"
)

func TestServiceTokenBoundary(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", "a sufficiently long password")
	if err != nil {
		t.Fatal(err)
	}
	token, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "agent", Scope: "operate", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/machines", "POST /v1/operator/test"}, SourceCIDRs: []string{"192.0.2.0/24"}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	calls := 0
	handler := func(w http.ResponseWriter, r *http.Request) {
		calls++
		p, ok := operatorauth.PrincipalFromContext(r.Context())
		if !ok || p.StableSubject() != "service:agent" {
			t.Error("wrong principal")
		}
		w.WriteHeader(204)
	}
	policies := map[string]operatorRoutePolicy{}
	for _, route := range []string{"GET /v1/operator/machines", "GET /v1/operator/jobs", "POST /v1/operator/test", "POST /v1/operator/admin", "GET /account/service-tokens"} {
		policy := operatorRoutePolicy{operatorauth.View, operatorJSON, operator.SourceKindOperatorAPI, operatorSecurityLocked, serviceEligible}
		if strings.HasPrefix(route, "POST") {
			policy.Permission = operatorauth.Operate
		}
		if strings.Contains(route, "admin") {
			policy.ServiceTokenEligible = serviceIneligible
			policy.Permission = operatorauth.Admin
		}
		if strings.Contains(route, "/account/") {
			policy.ServiceTokenEligible = serviceIneligible
			policy.Representation = operatorHTML
			policy.SourceKind = operator.SourceKindWeb
			policy.Permission = operatorauth.Admin
		}
		policies[route] = policy
		mux.HandleFunc(route, handler)
	}
	human := &boundaryAuthorizer{}
	b := newOperatorBoundary(mux, human, st, policies, testOperatorAuthority)
	request := func(method, path, peer, origin string) int {
		r := newBoundaryRequest(method, path, nil)
		r.RemoteAddr = peer
		r.Header.Set("Authorization", "Bearer "+secret)
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w.Code
	}
	for _, c := range []struct {
		method, path, peer, origin string
		status                     int
	}{{"GET", "/v1/operator/machines", "192.0.2.1:1234", "", 204}, {"GET", "/v1/operator/jobs", "192.0.2.1:1234", "", 401}, {"GET", "/v1/operator/machines", "198.51.100.1:1234", "", 401}, {"POST", "/v1/operator/admin", "192.0.2.1:1234", "", 401}, {"POST", "/v1/operator/test", "192.0.2.1:1234", "https://other.example.com", 403}, {"GET", "/account/service-tokens", "192.0.2.1:1234", "", 403}} {
		if got := request(c.method, c.path, c.peer, c.origin); got != c.status {
			t.Fatalf("%s %s: %d", c.method, c.path, got)
		}
	}
	if calls != 1 {
		t.Fatalf("unauthorized handler calls: %d", calls)
	}
	if len(human.snapshotCalls()) != 1 {
		t.Fatal("HTML did not use human auth")
	}
	audits, err := st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audits {
		if a.Action == "service-token-request" && a.AuthSubject == "service:agent" {
			found = true
		}
		if strings.Contains(a.Detail, secret) {
			t.Fatal("audit leaked secret")
		}
	}
	if !found {
		t.Fatal("missing service audit")
	}
	if err = st.RevokeServiceToken(token.ID, actor.AccountID); err != nil {
		t.Fatal(err)
	}
	if got := request("GET", "/v1/operator/machines", "192.0.2.1:1234", ""); got != 401 {
		t.Fatalf("revoked: %d", got)
	}
}

func TestServiceTokenFailureRateLimit(t *testing.T) {
	st := boundaryStore(t)
	mux := http.NewServeMux()
	route := "GET /v1/operator/machines"
	mux.HandleFunc(route, func(http.ResponseWriter, *http.Request) { t.Fatal("invalid token reached handler") })
	policy := operatorRoutePolicy{operatorauth.View, operatorJSON, operator.SourceKindOperatorAPI, operatorSecurityLocked, serviceEligible}
	b := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{route: policy}, testOperatorAuthority)
	for i := 0; i < 6; i++ {
		r := newBoundaryRequest("GET", "/v1/operator/machines", nil)
		r.RemoteAddr = "192.0.2.1:1234"
		r.Header.Set("Authorization", "Bearer cst_invalid")
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		want := 401
		if i == 5 {
			want = 429
		}
		if w.Code != want {
			t.Fatalf("attempt %d: %d", i, w.Code)
		}
	}
}

func TestServiceTokenManagementPlaintextOnce(t *testing.T) {
	h, st := localAccountHandler(t)
	actor, err := st.CreateFirstAdmin("alice", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	if w := accountRequest(h, "GET", "/account/service-tokens", "", adminSession(t, st)); w.Code != 303 {
		t.Fatalf("unenrolled session: %d", w.Code)
	}
	factor, err := st.BeginTOTPEnrollment(actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	enroll, _ := totp.Code(factor, time.Now().Unix()/30-1)
	if _, err = st.ConfirmTOTP(actor.AccountID, enroll); err != nil {
		t.Fatal(err)
	}
	cookie := adminSession(t, st)
	code, _ := totp.Code(factor, time.Now().Unix()/30)
	fields := url.Values{"name": {"agent"}, "scope": {"view"}, "expiry_days": {"90"}, "password": {usersPassword}, "code": {code}, "routes": {"GET /v1/operator/machines"}}
	w := accountRequest(h, "POST", "/account/service-tokens/create", fields.Encode(), cookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("create status: %d", w.Code)
	}
	secret := regexp.MustCompile(`cst_[a-f0-9]{64}`).FindString(w.Body.String())
	if secret == "" || strings.Count(w.Body.String(), secret) != 1 {
		t.Fatal("creation did not show exactly one secret")
	}
	hash := sha256.Sum256([]byte(serviceTokenCopyScript))
	if !strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'") || !strings.Contains(w.Body.String(), serviceTokenCopyScript) {
		t.Fatal("copy script missing exact CSP hash")
	}

	page := accountRequest(h, "GET", "/account/service-tokens", "", cookie)
	if page.Code != 200 || strings.Contains(page.Body.String(), secret) {
		t.Fatal("listing disclosed secret or failed")
	}
	tokens, err := st.ListServiceTokens()
	if err != nil || len(tokens) != 1 {
		t.Fatal("missing token")
	}
	// A bearer alone does not authorize token management or human security pages.
	for _, path := range []string{"/account/service-tokens", "/account/security", "/account/users"} {
		r := httptest.NewRequest("GET", "https://hub.example.com"+path, nil)
		r.Header.Set("Authorization", "Bearer "+secret)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		if rec.Code != 303 {
			t.Fatalf("bearer HTML %s: %d", path, rec.Code)
		}
	}
	fresh, _ := totp.Code(factor, time.Now().Unix()/30+1)
	revoke := url.Values{"id": {tokens[0].ID}, "password": {usersPassword}, "code": {fresh}}
	w = accountRequest(h, "POST", "/account/service-tokens/revoke", revoke.Encode(), cookie)
	if w.Code != 200 {
		t.Fatalf("revoke: %d", w.Code)
	}
	if _, err = st.AuthenticateServiceToken(secret, "GET /v1/operator/machines", "192.0.2.1", "view"); err == nil {
		t.Fatal("revocation not immediate")
	}
}

func TestServiceTokenManagementRejectsAdminScope(t *testing.T) {
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
	if _, err = st.ConfirmTOTP(actor.AccountID, enroll); err != nil {
		t.Fatal(err)
	}
	cookie := adminSession(t, st)
	code, _ := totp.Code(factor, time.Now().Unix()/30)
	fields := url.Values{"name": {"agent"}, "scope": {"admin"}, "expiry_days": {"90"}, "password": {usersPassword}, "code": {code}}
	w := accountRequest(h, "POST", "/account/service-tokens/create", fields.Encode(), cookie)
	if w.Code != 400 {
		t.Fatalf("admin create: %d", w.Code)
	}
	tokens, err := st.ListServiceTokens()
	if err != nil || len(tokens) != 0 {
		t.Fatal("admin service token stored")
	}
}

func TestServiceTokenManifestEligibility(t *testing.T) {
	for _, route := range []string{"GET /v1/operator/jobs-summary", "GET /v1/operator/approvals-summary", "GET /v1/operator/hub-status"} {
		policy, exists := operatorRoutePolicies[route]
		if !exists || policy.Permission != operatorauth.View || policy.ServiceTokenEligible != serviceEligible || !operatorPolicyAdmissible(route, policy) {
			t.Errorf("supervision view route lost token eligibility: %s", route)
		}
	}
	count := 0
	scriptCount := 0
	for route, policy := range operatorRoutePolicies {
		if !policy.ServiceTokenEligible.eligible() {
			continue
		}
		count++
		if policy.ServiceTokenEligible == serviceEligibleSelf {
			continue
		}
		if policy.ServiceTokenEligible == serviceEligibleReadScriptsOnly {
			scriptCount++
			if (route != "POST /v1/operator/script-runs/preview" && route != "POST /v1/operator/script-runs") || policy.Permission != operatorauth.Operate || !operatorPolicyAdmissible(route, policy) {
				t.Errorf("unexpected read-script eligibility: %s", route)
			}
			continue
		}
		if policy.Permission != operatorauth.View || policy.Representation != operatorJSON || policy.SourceKind != operator.SourceKindOperatorAPI || !strings.HasPrefix(route, "GET /v1/operator/") {
			t.Errorf("human-approval or non-read route eligible: %s", route)
		}
	}
	if scriptCount != 2 {
		t.Fatalf("read script routes=%d", scriptCount)
	}
	if count == 0 {
		t.Fatal("no read routes eligible")
	}
	// Leaving eligibility out of a new route must not confer token authority.
	future := operatorRoutePolicy{Permission: operatorauth.View, Representation: operatorJSON, SourceKind: operator.SourceKindOperatorAPI, SecurityProfile: operatorSecurityLocked}
	if future.ServiceTokenEligible.eligible() {
		t.Fatal("new route eligible by default")
	}
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "agent", Scope: "operate", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/future"}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/operator/future", func(http.ResponseWriter, *http.Request) { t.Fatal("new route reached") })
	b := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{"GET /v1/operator/future": future}, testOperatorAuthority)
	req := newBoundaryRequest("GET", "/v1/operator/future", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("future route: %d", rec.Code)
	}
}

func TestServiceTokenCannotSelfApproveExistingRoutes(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	var allowlist []string
	mux := http.NewServeMux()
	calls := 0
	for route, policy := range operatorRoutePolicies {
		if policy.Representation == operatorJSON {
			allowlist = append(allowlist, route)
			mux.HandleFunc(route, func(http.ResponseWriter, *http.Request) { calls++ })
		}
	}
	_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "legacy", Scope: "operate", ExpiresAt: time.Now().Add(time.Hour), Allowlist: allowlist}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	b := newOperatorBoundary(mux, nil, st, operatorRoutePolicies, testOperatorAuthority)
	for route, policy := range operatorRoutePolicies {
		if policy.Representation != operatorJSON || policy.ServiceTokenEligible.eligible() {
			continue
		}
		method, path, _ := strings.Cut(route, " ")
		path = regexp.MustCompile(`\{[^}]+\}`).ReplaceAllString(path, "test")
		req := newBoundaryRequest(method, path, nil)
		req.Header.Set("Authorization", "Bearer "+secret)
		// Independent request cases should not share the failure limiter budget.
		b.serviceAttempts = newIPLimiter(10, 5)
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("%s: %d", route, rec.Code)
		}
	}
	if calls != 0 {
		t.Fatalf("human-only routes called %d times", calls)
	}
}

func TestServiceTokenTrustedProxySource(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "agent", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/machines"}, SourceCIDRs: []string{"192.0.2.0/24"}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := clientip.Parse("203.0.113.0/24", "Fly-Client-IP")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/operator/machines", func(w http.ResponseWriter, r *http.Request) {
		p, _ := operatorauth.PrincipalFromContext(r.Context())
		if p.SourceAddr != "192.0.2.1" {
			t.Error("principal uses proxy address")
		}
		w.WriteHeader(204)
	})
	policy := operatorRoutePolicies["GET /v1/operator/machines"]
	b := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{"GET /v1/operator/machines": policy}, testOperatorAuthority)
	b.clientIP = resolver
	request := func(peer, forwarded, auth string) int {
		req := newBoundaryRequest("GET", "/v1/operator/machines", nil)
		req.RemoteAddr = peer
		req.Header.Set("Fly-Client-IP", forwarded)
		req.Header.Set("Authorization", "Bearer "+auth)
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		return rec.Code
	}
	if got := request("203.0.113.1:1234", "192.0.2.1", secret); got != 204 {
		t.Fatalf("trusted proxy: %d", got)
	}
	if got := request("198.51.100.2:1234", "192.0.2.1", secret); got != 401 {
		t.Fatalf("spoofed header accepted: %d", got)
	}
	if got := request("203.0.113.1:1234", "198.51.100.3", secret); got != 401 {
		t.Fatalf("trusted proxy CIDR bypass: %d", got)
	}
	for i := 0; i < 6; i++ {
		want := 401
		if i == 5 {
			want = 429
		}
		if got := request("203.0.113.1:1234", "198.51.100.1", "cst_invalid"); got != want {
			t.Fatalf("client failure %d: %d", i, got)
		}
	}
	if got := request("203.0.113.1:1234", "192.0.2.1", secret); got != 204 {
		t.Fatalf("proxy-shared limiter: %d", got)
	}
	audits, err := st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range audits {
		if a.AuthMethod == operatorauth.AuthMethodServiceToken && strings.HasPrefix(a.SourceAddr, "203.0.113.") {
			t.Fatal("audit recorded proxy")
		}
	}
	// Exercise the production constructor wiring, rather than only the fixture field.
	ui, err := web.New(st, "hub")
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHubHTTPHandler(&hub{store: st, clientIP: resolver}, ui, nil, testOperatorAuthority)
	if err != nil {
		t.Fatal(err)
	}
	req := newBoundaryRequest("GET", "/v1/operator/machines", nil)
	req.RemoteAddr = "203.0.113.1:1234"
	req.Header.Set("Fly-Client-IP", "192.0.2.1")
	req.Header.Set("Authorization", "Bearer "+secret)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("configured resolver not injected: %d", rec.Code)
	}
}

func TestServiceTokenAuditUsesFinalStatusOnce(t *testing.T) {
	for _, tc := range []struct {
		name           string
		handler        http.HandlerFunc
		method, origin string
		ok             bool
	}{
		{"implicit success", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }, "GET", "", true},
		{"empty success", func(http.ResponseWriter, *http.Request) {}, "GET", "", true},
		{"informational then failure", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(103); w.WriteHeader(500) }, "GET", "", false},
		{"first final wins", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204); w.WriteHeader(500) }, "GET", "", true},
		{"handler denial", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(400) }, "GET", "", false},
		{"handler error", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }, "GET", "", false},
		{"csrf denial", func(http.ResponseWriter, *http.Request) { t.Fatal("CSRF handler reached") }, "POST", "https://other.example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := boundaryStore(t)
			actor, err := st.CreateFirstAdmin("admin", usersPassword)
			if err != nil {
				t.Fatal(err)
			}
			route := tc.method + " /v1/operator/test"
			_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "agent", Scope: "operate", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{route}}, actor.AccountID)
			if err != nil {
				t.Fatal(err)
			}
			mux := http.NewServeMux()
			mux.HandleFunc(route, tc.handler)
			// A synthetic explicitly automated mutation exercises the CSRF wrapper; no
			// existing production mutation is eligible.
			permission := operatorauth.View
			if tc.method == "POST" {
				permission = operatorauth.Operate
			}
			policy := operatorRoutePolicy{permission, operatorJSON, operator.SourceKindOperatorAPI, operatorSecurityLocked, serviceEligible}
			b := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{route: policy}, testOperatorAuthority)
			req := newBoundaryRequest(tc.method, "/v1/operator/test", nil)
			req.Header.Set("Authorization", "Bearer "+secret)
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			rec := httptest.NewRecorder()
			b.ServeHTTP(rec, req)
			audits, err := st.Audit("", 100)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, a := range audits {
				if a.AuthMethod == operatorauth.AuthMethodServiceToken {
					count++
					if a.AuthSubject != "service:agent" || a.OK != tc.ok {
						t.Errorf("wrong service audit outcome: %s %v", a.AuthSubject, a.OK)
					}
				}
			}
			if count != 1 {
				t.Fatalf("service request audited %d times", count)
			}
		})
	}
}

func TestServiceTokenManagementRejectsIneligibleAllowlist(t *testing.T) {
	for _, allow := range []string{"", "POST /v1/operator/deployments/{id}/continuations", "POST /v1/operator/machines/{id}/diagnostic-noop-jobs", "GET /v1/operator/not-registered", "GET  /v1/operator/machines"} {
		t.Run(allow, func(t *testing.T) {
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
			if _, err = st.ConfirmTOTP(actor.AccountID, enroll); err != nil {
				t.Fatal(err)
			}
			cookie := adminSession(t, st)
			code, _ := totp.Code(factor, time.Now().Unix()/30)
			fields := url.Values{"name": {"agent"}, "scope": {"operate"}, "expiry_days": {"90"}, "password": {usersPassword}, "code": {code}, "routes": {allow}}
			rec := accountRequest(h, "POST", "/account/service-tokens/create", fields.Encode(), cookie)
			if rec.Code != 400 {
				t.Fatalf("create ineligible allowlist: %d", rec.Code)
			}
			tokens, err := st.ListServiceTokens()
			if err != nil || len(tokens) != 0 {
				t.Fatal("ineligible service token created")
			}
		})
	}
}

func TestServiceTokenRateLimitedAuditWritesAreBounded(t *testing.T) {
	st := boundaryStore(t)
	mux := http.NewServeMux()
	route := "GET /v1/operator/machines"
	mux.HandleFunc(route, func(http.ResponseWriter, *http.Request) { t.Fatal("invalid token reached handler") })
	b := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{route: operatorRoutePolicies[route]}, testOperatorAuthority)
	for i := 0; i < denialAuditBurst+20; i++ {
		req := newBoundaryRequest("GET", "/v1/operator/machines", nil)
		req.Header.Set("Authorization", "Bearer cst_invalid")
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		if i >= 5 && rec.Code != 429 {
			t.Fatalf("rate limit: %d", rec.Code)
		}
	}
	audits, err := st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, a := range audits {
		if a.Action == store.AuditOperatorDenied {
			count++
		}
	}
	if count != denialAuditBurst {
		t.Fatalf("denial writes %d, want bounded burst %d", count, denialAuditBurst)
	}
}

func TestServiceTokenPanicAuditIsFailure(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	route := "GET /v1/operator/machines"
	_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "agent", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{route}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(route, func(http.ResponseWriter, *http.Request) { panic("test handler failure") })
	b := newOperatorBoundary(mux, nil, st, map[string]operatorRoutePolicy{route: operatorRoutePolicies[route]}, testOperatorAuthority)
	req := newBoundaryRequest("GET", "/v1/operator/machines", nil)
	req.Header.Set("Authorization", "Bearer "+secret)
	func() {
		defer func() {
			if recover() == nil {
				t.Error("handler panic was swallowed")
			}
		}()
		b.ServeHTTP(httptest.NewRecorder(), req)
	}()
	audits, err := st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, a := range audits {
		if a.AuthMethod == operatorauth.AuthMethodServiceToken {
			count++
			if a.OK || !strings.Contains(a.Detail, "500") {
				t.Error("panic audited as success")
			}
		}
	}
	if count != 1 {
		t.Fatalf("panic audit count: %d", count)
	}
}

func managementAuditFixture(t *testing.T, enrolled bool) (*http.ServeMux, *store.Store, operatorauth.Principal, string) {
	t.Helper()
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("alice", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	if enrolled {
		factor, err := st.BeginTOTPEnrollment(actor.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		code, _ := totp.Code(factor, time.Now().Unix()/30-1)
		if _, err = st.ConfirmTOTP(actor.AccountID, code); err != nil {
			t.Fatal(err)
		}
	}
	resolver, err := clientip.Parse("203.0.113.0/24", "Fly-Client-IP")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerServiceTokenRoutes(mux, st, resolver)
	principal := operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, TailnetUserID: "local:" + actor.AccountID, TailnetUserLogin: "alice", SourceAddr: "203.0.113.1", GrantedCapabilities: operatorauth.CapabilityNames{Admin: "admin"}}
	return mux, st, principal, "management-audit-test/1"
}

func managementAuditRequest(h http.Handler, principal operatorauth.Principal, action string, fields url.Values, peer, agent string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "https://hub.example.com/account/service-tokens/"+action, strings.NewReader(fields.Encode()))
	req.RemoteAddr = peer
	req.Header.Set("Fly-Client-IP", "192.0.2.1")
	req.Header.Set("User-Agent", agent)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, operatorauth.WithPrincipal(req, principal))
	return rec
}

func TestServiceTokenManagementDeniedAuditsIncludeRateLimitAndMetadata(t *testing.T) {
	for _, action := range []string{"create", "revoke"} {
		t.Run(action, func(t *testing.T) {
			mux, st, principal, agent := managementAuditFixture(t, true)
			target := "agent-name"
			field := "name"
			if action == "revoke" {
				target = "00000000-0000-4000-8000-000000000001"
				field = "id"
			}
			fields := url.Values{field: {target}, "password": {"incorrect-test-password"}, "code": {"invalid-test-code"}}
			for i := 0; i < 6; i++ {
				rec := managementAuditRequest(mux, principal, action, fields, "203.0.113.1:1234", agent)
				want := 400
				if i == 5 {
					want = 429
				}
				if rec.Code != want {
					t.Fatalf("attempt %d: %d", i, rec.Code)
				}
				if i < 5 && !strings.Contains(rec.Body.String(), "Password or code incorrect.") {
					t.Fatal("factor error not generic")
				}
				if i == 5 && !strings.Contains(rec.Body.String(), "Rate limited") {
					t.Fatal("missing rate limit error")
				}
				if strings.Contains(rec.Body.String(), "incorrect-test-password") || strings.Contains(rec.Body.String(), "invalid-test-code") {
					t.Fatal("credentials echoed")
				}

			}
			audits, err := st.Audit("", 100)
			if err != nil {
				t.Fatal(err)
			}
			denied, limited, passwordChecks := 0, 0, 0
			for _, a := range audits {
				if a.Action == store.AuditAction("service-token-"+action+"-denied") {
					denied++
					if a.OK || a.AuthSubject != principal.StableSubject() || a.AuthMethod != principal.AuthMethod || a.SourceAddr != "192.0.2.1" || a.UserAgent != agent || a.Subject != target {
						t.Error("denied request metadata mismatch")
					}
					if a.Detail == "HTTP status 429" {
						limited++
					}
				}
				if a.Action == store.AuditHubLoginFailed {
					passwordChecks++
					if a.SourceAddr != "192.0.2.1" || a.UserAgent != agent {
						t.Error("password verification metadata missing")
					}
				}
				if strings.Contains(a.Subject, "incorrect-test-password") || strings.Contains(a.Detail, "invalid-test-code") {
					t.Fatal("credential in audit")
				}
			}
			if denied != 6 || limited != 1 || passwordChecks != 5 {
				t.Fatalf("denied=%d limited=%d password checks=%d", denied, limited, passwordChecks)
			}
			// A second client behind the same trusted proxy must have its own budget.
			req := httptest.NewRequest("POST", "https://hub.example.com/account/service-tokens/"+action, strings.NewReader(fields.Encode()))
			req.RemoteAddr = "203.0.113.1:1234"
			req.Header.Set("Fly-Client-IP", "192.0.2.2")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, operatorauth.WithPrincipal(req, principal))
			if rec.Code != 400 {
				t.Fatalf("proxy-shared management limit: %d", rec.Code)
			}
		})
	}
}

func TestServiceTokenManagementDeniedMetadataForOtherFailures(t *testing.T) {
	for _, tc := range []struct {
		name, action, peer, password, code string
		enrolled                           bool
		want                               int
	}{
		{"bad factor", "create", "203.0.113.1:1234", usersPassword, "invalid-test-code", true, 400},
		{"missing MFA", "revoke", "203.0.113.1:1234", usersPassword, "invalid-test-code", false, 403},
		{"untrusted forwarded header", "revoke", "198.51.100.1:1234", "incorrect-test-password", "invalid-test-code", true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mux, st, principal, agent := managementAuditFixture(t, tc.enrolled)
			field, target := "name", "agent-name"
			if tc.action == "revoke" {
				field = "id"
				target = "00000000-0000-4000-8000-000000000001"
			}
			rec := managementAuditRequest(mux, principal, tc.action, url.Values{field: {target}, "password": {tc.password}, "code": {tc.code}}, tc.peer, agent)
			if rec.Code != tc.want {
				t.Fatalf("failure status: %d", rec.Code)
			}
			source := "192.0.2.1"
			if strings.HasPrefix(tc.peer, "198.") {
				source = "198.51.100.1"
			}
			audits, err := st.Audit("", 100)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			factorFailure := false
			for _, a := range audits {
				if a.Action == store.AuditAction("service-token-"+tc.action+"-denied") {
					count++
					if a.SourceAddr != source || a.UserAgent != agent || a.Subject != target || a.AuthSubject != principal.StableSubject() || a.OK {
						t.Error("denied request metadata mismatch")
					}
				}
				if a.Action == store.AuditMFAFailed {
					factorFailure = true
					if a.SourceAddr != source || a.UserAgent != agent {
						t.Error("factor verification metadata missing")
					}
				}
			}
			if count != 1 {
				t.Fatalf("denial audits: %d", count)
			}
			if tc.name == "bad factor" && !factorFailure {
				t.Fatal("missing factor failure audit")
			}
		})
	}
}

func TestServiceTokenManagementAuditOmitsUnsafeTargets(t *testing.T) {
	secret := "cst_" + strings.Repeat("a", 64)
	for _, action := range []string{"create", "revoke"} {
		t.Run(action, func(t *testing.T) {
			mux, st, principal, agent := managementAuditFixture(t, true)
			field := "name"
			if action == "revoke" {
				field = "id"
			}
			rec := managementAuditRequest(mux, principal, action, url.Values{field: {secret}, "password": {"incorrect-test-password"}}, "203.0.113.1:1234", agent)
			if rec.Code != 400 {
				t.Fatalf("failure status: %d", rec.Code)
			}
			audits, err := st.Audit("", 100)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, a := range audits {
				if strings.Contains(a.Subject, secret) || strings.Contains(a.Detail, secret) {
					t.Fatal("token persisted in audit")
				}
				if a.Action == store.AuditAction("service-token-"+action+"-denied") {
					found = true
					if a.Subject != "unavailable" {
						t.Fatal("unsafe target included")
					}
				}
			}
			if !found {
				t.Fatal("missing management denial")
			}
		})
	}
}

func TestServiceTokenManagementBoundaryDenialsAudited(t *testing.T) {
	for _, rejection := range []string{"csrf", "mfa"} {
		for _, action := range []string{"create", "revoke"} {
			t.Run(rejection+"/"+action, func(t *testing.T) {
				t.Setenv("CLAWCTL_TRUSTED_PROXIES", "203.0.113.0/24")
				t.Setenv("CLAWCTL_CLIENT_IP_HEADER", "Fly-Client-IP")
				h, st := localAccountHandler(t)
				actor, err := st.CreateFirstAdmin("alice", usersPassword)
				if err != nil {
					t.Fatal(err)
				}
				if rejection == "csrf" {
					factor, err := st.BeginTOTPEnrollment(actor.AccountID)
					if err != nil {
						t.Fatal(err)
					}
					code, _ := totp.Code(factor, time.Now().Unix()/30-1)
					if _, err = st.ConfirmTOTP(actor.AccountID, code); err != nil {
						t.Fatal(err)
					}
				}
				target, field := "agent-name", "name"
				if action == "revoke" {
					target, field = "00000000-0000-4000-8000-000000000001", "id"
				}
				r := httptest.NewRequest("POST", "https://hub.example.com/account/service-tokens/"+action, strings.NewReader(url.Values{field: {target}}.Encode()))
				r.RemoteAddr = "203.0.113.1:1234"
				r.Header.Set("Fly-Client-IP", "192.0.2.1")
				r.Header.Set("User-Agent", "management-boundary-test/1")
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				if rejection == "csrf" {
					r.Header.Set("Origin", "https://other.example.com")
				}
				r.AddCookie(adminSession(t, st))
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				want := http.StatusForbidden
				if rejection == "mfa" {
					want = http.StatusSeeOther
				}
				if w.Code != want {
					t.Fatalf("status = %d, want %d", w.Code, want)
				}
				entries, err := st.Audit("", 100)
				if err != nil {
					t.Fatal(err)
				}
				count := 0
				for _, entry := range entries {
					if entry.Action != store.AuditAction("service-token-"+action+"-denied") {
						continue
					}
					count++
					if entry.OK || entry.Subject != target || entry.AuthSubject != "local-user:"+actor.AccountID || entry.AuthMethod != operatorauth.AuthMethodLocalAccountSession || entry.SourceAddr != "192.0.2.1" || entry.UserAgent != "management-boundary-test/1" {
						t.Fatalf("incorrect denial metadata: %+v", entry)
					}
				}
				if count != 1 {
					t.Fatalf("management denial count = %d", count)
				}
			})
		}
	}
}

func TestServiceTokenManagementCapabilityDenialsAudited(t *testing.T) {
	for _, action := range []string{"create", "revoke"} {
		t.Run(action, func(t *testing.T) {
			mux, st, principal, agent := managementAuditFixture(t, true)
			principal.GrantedCapabilities = operatorauth.CapabilityNames{View: "view"}
			authorizer := &boundaryAuthorizer{decision: operatorauth.Decision{HTTPStatus: 403, Code: operatorauth.CapabilityRequired, Principal: principal}}
			boundary := newOperatorBoundary(mux, authorizer, st, operatorRoutePolicies, testOperatorAuthority)
			boundary.clientIP, _ = clientip.Parse("203.0.113.0/24", "Fly-Client-IP")
			field, target := "name", "agent-name"
			if action == "revoke" {
				field, target = "id", "00000000-0000-4000-8000-000000000001"
			}
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { r.Host = testOperatorAuthority; boundary.ServeHTTP(w, r) })
			w := managementAuditRequest(handler, principal, action, url.Values{field: {target}}, "203.0.113.1:1234", agent)
			if w.Code != 403 {
				t.Fatalf("status = %d", w.Code)
			}
			entries, err := st.Audit("", 100)
			if err != nil {
				t.Fatal(err)
			}
			count := 0
			for _, entry := range entries {
				if entry.Action != store.AuditAction("service-token-"+action+"-denied") {
					continue
				}
				count++
				if entry.OK || entry.Subject != target || entry.AuthSubject != principal.StableSubject() || entry.SourceAddr != "192.0.2.1" || entry.UserAgent != agent {
					t.Fatalf("incorrect denial metadata: %+v", entry)
				}
			}
			if count != 1 {
				t.Fatalf("denial count = %d", count)
			}
		})
	}
}

func TestServiceTokenManagementScriptAllowlistScope(t *testing.T) {
	for _, scope := range []string{"view", "operate"} {
		t.Run(scope, func(t *testing.T) {
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
			if _, err = st.ConfirmTOTP(actor.AccountID, enroll); err != nil {
				t.Fatal(err)
			}
			cookie := adminSession(t, st)
			code, _ := totp.Code(factor, time.Now().Unix()/30)
			fields := url.Values{"name": {"hermes"}, "scope": {scope}, "expiry_days": {"90"}, "password": {usersPassword}, "code": {code}, "routes": {"POST /v1/operator/script-runs/preview", "POST /v1/operator/script-runs"}}
			rec := accountRequest(h, "POST", "/account/service-tokens/create", fields.Encode(), cookie)
			want := 200
			wantTokens := 1
			if scope == "view" {
				want = 400
				wantTokens = 0
			}
			if rec.Code != want {
				t.Fatalf("creation status=%d", rec.Code)
			}
			tokens, err := st.ListServiceTokens()
			if err != nil || len(tokens) != wantTokens {
				t.Fatalf("tokens=%d err=%v", len(tokens), err)
			}
		})
	}
}
