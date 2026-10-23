package store

import (
	"database/sql"
	"encoding/json"
	"slices"
	"time"
)

// Match the complete historical preset, never a subset or a token name.
func migrateHermesServiceRoutes(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT id,allowlist FROM service_tokens WHERE revoked_at IS NULL`)
	if err != nil {
		return err
	}
	legacy := hermesLegacyServiceRoutes()
	slices.Sort(legacy)
	var ids []string
	for rows.Next() {
		var id, raw string
		if err = rows.Scan(&id, &raw); err != nil {
			rows.Close()
			return err
		}
		var routes []string
		if json.Unmarshal([]byte(raw), &routes) != nil {
			continue
		}
		slices.Sort(routes)
		if slices.Equal(routes, legacy) {
			ids = append(ids, id)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	raw, err := json.Marshal(HermesServiceRoutes())
	if err != nil {
		return err
	}
	auditStore := &Store{nowFn: func() time.Time { return time.Now().UTC() }}
	for _, id := range ids {
		if _, err = tx.Exec(`UPDATE service_tokens SET allowlist=? WHERE id=?`, string(raw), id); err != nil {
			return err
		}
		if err = auditStore.recordAuditTx(tx, AuditEntry{Action: "service-token-hermes-preset-migrate", Subject: id, AuthSubject: "system:migration", AuthMethod: "migration", SourceAddr: "local", OK: true, Detail: "Expanded Hermes preset with routine read routes"}); err != nil {
			return err
		}
	}
	return tx.Commit()
}
