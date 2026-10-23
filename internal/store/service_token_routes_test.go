package store

import (
	"strings"
	"testing"
	"time"
)

func TestUpdateServiceTokenRoutes(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	admin, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	oldRoute, nextRoute := "GET /v1/operator/machines", "GET /v1/operator/jobs"
	token, secret, err := s.CreateServiceToken(ServiceToken{Name: "reader", Scope: "view", ExpiresAt: s.now().Add(time.Hour), Allowlist: []string{oldRoute}}, admin.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	for _, routes := range [][]string{nil, {nextRoute, nextRoute}, {"bad"}, {"POST /v1/operator/script-runs"}, {"POST /v1/operator/enrollment-tokens"}} {
		if err := s.UpdateServiceTokenRoutes(token.ID, routes, admin.AccountID); err == nil {
			t.Fatalf("accepted invalid routes %v", routes)
		}
	}
	if err := s.UpdateServiceTokenRoutes(token.ID, []string{nextRoute}, "missing"); err == nil {
		t.Fatal("nonadmin accepted")
	}
	if err := s.UpdateServiceTokenRoutes(token.ID, []string{nextRoute}, admin.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AuthenticateServiceToken(secret, oldRoute, "192.0.2.1", "view"); err == nil {
		t.Fatal("removed route accepted")
	}
	got, err := s.AuthenticateServiceToken(secret, nextRoute, "192.0.2.1", "view")
	if err != nil || got.Scope != token.Scope || !got.ExpiresAt.Equal(token.ExpiresAt) {
		t.Fatal("new grants or immutable fields incorrect")
	}
	rows, err := s.DB().Query(`SELECT detail FROM audit_log WHERE action='service-token-routes-edit' AND subject=?`, token.ID)
	if err != nil {
		t.Fatal(err)
	}
	var details string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatal(err)
		}
		details += detail
	}
	rows.Close()
	if !strings.Contains(details, "old: allowed -> new: denied; "+oldRoute) || !strings.Contains(details, "old: denied -> new: allowed; "+nextRoute) || strings.Contains(details, secret) {
		t.Fatal("missing safe complete grant diff")
	}
	if err := s.RevokeServiceToken(token.ID, admin.AccountID); err != nil {
		t.Fatal(err)
	}
	if err := s.UpdateServiceTokenRoutes(token.ID, []string{oldRoute}, admin.AccountID); err == nil {
		t.Fatal("revoked token editable")
	}
}
