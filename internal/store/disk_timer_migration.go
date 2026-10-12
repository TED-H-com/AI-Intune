package store

import (
	"database/sql"
	"strings"
)

// Rebuild P2-05 tables transactionally: SQLite cannot extend a CHECK constraint
// or replace the old agent-clock primary key with a Hub receipt sequence in place.
func migrateDiskTimerEvidence(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var schema string
	err = tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name='disk_ownership'`).Scan(&schema)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil && !strings.Contains(schema, "transition_nonce") {
		for _, q := range []string{
			`CREATE TABLE disk_ownership_new (machine_id TEXT NOT NULL REFERENCES machine_registry(machine_id),scope TEXT NOT NULL CHECK(scope IN ('root','user')),state TEXT NOT NULL CHECK(state IN ('local-owned','handoff-pending','hub-owned','rolled-back','rollback-pending')),revision INTEGER NOT NULL,changed_at TEXT NOT NULL,transition_nonce TEXT NOT NULL DEFAULT '',PRIMARY KEY(machine_id,scope))`,
			`INSERT INTO disk_ownership_new SELECT machine_id,scope,state,revision,changed_at,CASE WHEN state='handoff-pending' THEN lower(hex(randomblob(32))) ELSE '' END FROM disk_ownership`,
			`DROP TABLE disk_ownership`, `ALTER TABLE disk_ownership_new RENAME TO disk_ownership`,
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	err = tx.QueryRow(`SELECT sql FROM sqlite_schema WHERE type='table' AND name='disk_timer_observations'`).Scan(&schema)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil && !strings.Contains(schema, "receipt_seq") {
		for _, q := range []string{
			`CREATE TABLE disk_timer_observations_new (receipt_seq INTEGER PRIMARY KEY AUTOINCREMENT,machine_id TEXT NOT NULL REFERENCES machine_registry(machine_id),scope TEXT NOT NULL,observed_at TEXT NOT NULL,received_at TEXT NOT NULL,body TEXT NOT NULL)`,
			// Legacy rows have no trusted receipt. Retain their latest display evidence
			// as stale, never invent a fresh receipt that could approve a handoff.
			`INSERT INTO disk_timer_observations_new(machine_id,scope,observed_at,received_at,body) SELECT machine_id,scope,observed_at,'1970-01-01T00:00:00.000000000Z',json_set(body,'$.received_at','1970-01-01T00:00:00Z','$.receipt_sequence',0) FROM disk_timer_observations o WHERE rowid IN (SELECT MAX(rowid) FROM disk_timer_observations GROUP BY machine_id,scope) ORDER BY rowid`,
			`DROP TABLE disk_timer_observations`, `ALTER TABLE disk_timer_observations_new RENAME TO disk_timer_observations`,
		} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
