package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
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

// Parse legacy timestamps in Go: SQLite date functions lose subsecond precision.
// Adding each column and backfilling it in one transaction makes retries safe.
func migrateUsageSnapshotTimes(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, spec := range []struct{ table, column, timestamp string }{
		{"usage_accounts", "last_seen_ns", "last_seen"},
		{"usage_sessions", "end_ns", "json_extract(body, '$.End')"},
		{"usage_jobs", "last_seen_ns", "json_extract(body, '$.LastSeen')"},
	} {
		columns, err := columnSet(tx, spec.table)
		if err != nil {
			return err
		}
		if columns[spec.column] {
			continue
		}
		if _, err := tx.Exec("ALTER TABLE " + spec.table + " ADD COLUMN " + spec.column + " INTEGER NOT NULL DEFAULT 0"); err != nil {
			return err
		}
		rows, err := tx.Query("SELECT rowid, " + spec.timestamp + " FROM " + spec.table)
		if err != nil {
			return err
		}
		var backfill []struct{ rowID, ns int64 }
		for rows.Next() {
			var rowID int64
			var raw string
			if err := rows.Scan(&rowID, &raw); err != nil {
				rows.Close()
				return err
			}
			stamp, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				rows.Close()
				return fmt.Errorf("%s timestamp: %w", spec.table, err)
			}
			backfill = append(backfill, struct{ rowID, ns int64 }{rowID, stamp.UnixNano()})
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		for _, row := range backfill {
			if _, err := tx.Exec("UPDATE "+spec.table+" SET "+spec.column+"=? WHERE rowid=?", row.ns, row.rowID); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}
