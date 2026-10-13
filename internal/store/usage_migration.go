package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// Rebuild the legacy parent on one connection with FK enforcement temporarily
// disabled, preserving child references and all immutable-policy triggers.
func migrateUsagePolicyKind(db *sql.DB) error {
	var ddl string
	if e := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='ops_policies'`).Scan(&ddl); errors.Is(e, sql.ErrNoRows) {
		return nil
	} else if e != nil {
		return e
	}
	if strings.Contains(ddl, "'usage'") {
		return nil
	}
	conn, e := db.Conn(context.Background())
	if e != nil {
		return e
	}
	defer conn.Close()
	if _, e = conn.ExecContext(context.Background(), `PRAGMA foreign_keys=OFF`); e != nil {
		return e
	}
	defer conn.ExecContext(context.Background(), `PRAGMA foreign_keys=ON`)
	tx, e := conn.BeginTx(context.Background(), nil)
	if e != nil {
		return e
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE ops_policies_usage_migration (
            id TEXT NOT NULL,
            kind TEXT NOT NULL CHECK(kind IN ('disk','usage')),
            revision INTEGER NOT NULL CHECK(revision>0),
            body TEXT NOT NULL,
            digest TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at TEXT NOT NULL,
            superseded_at TEXT,
            PRIMARY KEY(id,revision)
        )`,
		`INSERT INTO ops_policies_usage_migration SELECT * FROM ops_policies`,
		`DROP TRIGGER IF EXISTS ops_policy_no_delete`,
		`DROP TABLE ops_policies`,
		`ALTER TABLE ops_policies_usage_migration RENAME TO ops_policies`,
	}
	for _, statement := range statements {
		if _, e = tx.Exec(statement); e != nil {
			return e
		}
	}
	rows, e := tx.Query(`PRAGMA foreign_key_check`)
	if e != nil {
		return e
	}
	bad := rows.Next()
	if e = rows.Err(); e != nil {
		rows.Close()
		return e
	}
	e = rows.Close()
	if e != nil {
		return e
	}
	if bad {
		return errors.New("store: usage policy migration foreign key violation")
	}
	return tx.Commit()
}
