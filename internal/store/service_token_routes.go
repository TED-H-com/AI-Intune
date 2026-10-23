package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

// UpdateServiceTokenRoutes changes only the current, live credential's grants.
// Callers must restrict routes to the Hub's service-token route manifest.
// Rotation and editing share a write transaction, so a concurrent rotation
// cannot silently inherit grants different from those reviewed by the admin.
func (s *Store) UpdateServiceTokenRoutes(id string, routes []string, actor string) error {
	if len(routes) == 0 || len(routes) > 128 {
		return ErrServiceToken
	}
	tx, err := s.beginWrite(context.Background(), "update_service_token_routes")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_accounts WHERE account_id=? AND role='admin' AND disabled_at IS NULL`, actor).Scan(&n); err != nil || n != 1 {
		return ErrServiceToken
	}
	t, err := scanServiceToken(tx.QueryRow("SELECT "+serviceTokenColumns+" FROM service_tokens WHERE id=?", id))
	if err != nil || t.RevokedAt != nil || t.RotatedAt != nil || !t.ExpiresAt.After(s.now()) {
		return ErrServiceToken
	}
	old, next := map[string]bool{}, map[string]bool{}
	for _, route := range t.Allowlist {
		old[route] = true
	}
	for _, route := range routes {
		if next[route] || !validServiceRoute(route) || (operatorauth.OperatorAdminRoute(route) && t.Scope != operatorauth.ServiceScopeOperatorAdmin) || (t.Scope == "view" && (route == "POST /v1/operator/script-runs" || route == "POST /v1/operator/script-runs/preview")) {
			return ErrServiceToken
		}
		next[route] = true
	}
	data, _ := json.Marshal(routes)
	if _, err = tx.Exec(`UPDATE service_tokens SET allowlist=? WHERE id=?`, string(data), id); err != nil {
		return err
	}
	audit := func(detail string) error {
		return s.recordAuditTx(tx, AuditEntry{At: s.now().UTC(), Action: "service-token-routes-edit", AuthSubject: "local-user:" + actor, AuthMethod: "local-account-session", Subject: id, Detail: detail, OK: true})
	}
	// One bounded entry per changed route preserves the full diff without audit truncation.
	for _, route := range t.Allowlist {
		if !next[route] {
			if err = audit("old: allowed -> new: denied; " + route); err != nil {
				return err
			}
		}
	}
	for _, route := range routes {
		if !old[route] {
			if err = audit("old: denied -> new: allowed; " + route); err != nil {
				return err
			}
		}
	}
	if err = audit("Route edit complete; scope, expiry and secret unchanged at " + s.now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	return tx.Commit()
}
