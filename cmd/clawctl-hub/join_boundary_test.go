package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func TestJoinRoutePoliciesAndFreshMFA(t *testing.T) {
	for _, route := range []string{"GET /machines/join", "GET /v1/operator/joins"} {
		if operatorRoutePolicies[route].Permission != operatorauth.View {
			t.Fatal("join read requires View")
		}
	}
	policy := operatorRoutePolicies["POST /machines/join/decide"]
	if policy.Permission != operatorauth.Admin || policy.ServiceTokenEligible != serviceIneligible || policy.SourceKind != operator.SourceKindWeb {
		t.Fatal("join decision must be a human Admin form")
	}
	for _, age := range []time.Duration{time.Minute, 2 * time.Hour} {
		b := &operatorBoundary{cloud: &cloudBoundaryConfig{requireMFA: true, adminMFAWindow: time.Hour}}
		r := httptest.NewRequest("POST", "https://hub.example.com/machines/join/decide", strings.NewReader("join_id=ABCD-2345&display_name=Host-B&decision=approve"))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r = operatorauth.WithPrincipal(r, operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, MFAVerifiedAt: time.Now().Add(-age)})
		w := httptest.NewRecorder()
		allowed := b.authorizeActionMFA(w, r, "POST /machines/join/decide", policy)
		if allowed != (age < time.Hour) {
			t.Fatal("join does not follow enrollment MFA window")
		}
		if !allowed && w.Code != http.StatusForbidden {
			t.Fatal("missing step-up challenge")
		}
	}
}
