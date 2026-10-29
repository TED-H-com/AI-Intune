package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/url"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

const errorTimeFormat = "2006-01-02T15:04:05.000000000Z"

// Error telemetry owns a separate WAL file and writer, independent of fleet state.
func openErrors(path string) (*sql.DB, error) {
	u := &url.URL{Scheme: "file", Path: path + ".errors.sqlite"}
	q := u.Query()
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "synchronous(NORMAL)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS error_records (
 machine_id TEXT NOT NULL, fingerprint TEXT NOT NULL, ts TEXT NOT NULL,
 component TEXT NOT NULL, count INTEGER NOT NULL, received_at TEXT NOT NULL, body TEXT NOT NULL,
 PRIMARY KEY(machine_id,fingerprint,ts));
 CREATE INDEX IF NOT EXISTS error_records_time ON error_records(ts);
 CREATE INDEX IF NOT EXISTS error_records_retention ON error_records(received_at);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (s *Store) InsertErrors(ctx context.Context, records []errlog.Record) (int64, error) {
	tx, err := s.errorsDB.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, `INSERT OR IGNORE INTO error_records VALUES (?,?,?,?,?,?,?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	var inserted int64
	for _, r := range records {
		body, err := json.Marshal(r)
		if err != nil {
			return 0, err
		}
		res, err := stmt.ExecContext(ctx, r.MachineID, r.Fingerprint, r.TS.UTC().Format(errorTimeFormat), r.Component, r.Count, fmtTime(s.now()), string(body))
		if err != nil {
			return 0, err
		}
		n, _ := res.RowsAffected()
		inserted += n
	}
	return inserted, tx.Commit()
}

type ErrorFilter struct {
	Since              time.Time
	Component, Machine string
	Limit              int
}

func (s *Store) ListErrors(ctx context.Context, f ErrorFilter) ([]errlog.Record, error) {
	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 200
	}
	rows, err := s.errorsDB.QueryContext(ctx, `SELECT body FROM error_records WHERE ts>=? AND (?='' OR component=?) AND (?='' OR machine_id=?) ORDER BY ts DESC,machine_id,fingerprint LIMIT ?`, f.Since.UTC().Format(errorTimeFormat), f.Component, f.Component, f.Machine, f.Machine, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []errlog.Record{}
	for rows.Next() {
		var body string
		var r errlog.Record
		if err = rows.Scan(&body); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(body), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

type ErrorAggregate struct {
	Fingerprint string   `json:"fingerprint"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	Count       int64    `json:"count"`
	Machines    []string `json:"machines"`
}

func (s *Store) TopErrors(ctx context.Context, since time.Time) ([]ErrorAggregate, error) {
	rows, err := s.errorsDB.QueryContext(ctx, `SELECT fingerprint,MIN(ts),MAX(ts),SUM(count),json_group_array(DISTINCT machine_id) FROM error_records WHERE ts>=? GROUP BY fingerprint ORDER BY SUM(count) DESC,fingerprint LIMIT 200`, since.UTC().Format(errorTimeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ErrorAggregate{}
	for rows.Next() {
		var a ErrorAggregate
		var machines string
		if err = rows.Scan(&a.Fingerprint, &a.FirstSeen, &a.LastSeen, &a.Count, &machines); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(machines), &a.Machines); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) pruneErrors(now time.Time, dry bool) (PruneCount, error) {
	c := PruneCount{Table: "error_records", Older: now.Add(-30 * 24 * time.Hour)}
	if dry {
		err := s.errorsDB.QueryRow(`SELECT COUNT(*) FROM error_records WHERE received_at < ?`, fmtTime(c.Older)).Scan(&c.Deleted)
		return c, err
	}
	res, err := s.errorsDB.Exec(`DELETE FROM error_records WHERE received_at < ?`, fmtTime(c.Older))
	if err != nil {
		return c, err
	}
	c.Deleted, err = res.RowsAffected()
	return c, err
}
