package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

// IssueErrors reads the complete window, without the interactive API's row limit.
func (s *Store) IssueErrors(ctx context.Context, since time.Time) ([]errlog.Record, error) {
	rows, err := s.errorsDB.QueryContext(ctx, `SELECT body FROM error_records WHERE ts>=? ORDER BY ts,fingerprint,machine_id`, since.UTC().Format(errorTimeFormat))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []errlog.Record
	for rows.Next() {
		var b string
		var r errlog.Record
		if err := rows.Scan(&b); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(b), &r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) InitIssueFiler(ctx context.Context) error {
	_, err := s.errorsDB.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS issue_actions(repo TEXT NOT NULL, fingerprint TEXT NOT NULL, last_seen TEXT NOT NULL, commented_at TEXT NOT NULL, PRIMARY KEY(repo,fingerprint));
 CREATE TABLE IF NOT EXISTS issue_budget(repo TEXT NOT NULL, created_at INTEGER NOT NULL, digest INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS issue_budget_repo_time ON issue_budget(repo,created_at);`)
	return err
}
func (s *Store) IssueAction(ctx context.Context, repo, fp string) (seen, comment string, err error) {
	err = s.errorsDB.QueryRowContext(ctx, `SELECT last_seen,commented_at FROM issue_actions WHERE repo=? AND fingerprint=?`, repo, fp).Scan(&seen, &comment)
	if err == sql.ErrNoRows {
		err = nil
	}
	return
}
func (s *Store) SaveIssueAction(ctx context.Context, repo, fp, seen string, at time.Time) error {
	_, err := s.errorsDB.ExecContext(ctx, `INSERT INTO issue_actions VALUES(?,?,?,?) ON CONFLICT(repo,fingerprint) DO UPDATE SET last_seen=excluded.last_seen,commented_at=excluded.commented_at`, repo, fp, seen, at.UTC().Format(time.RFC3339Nano))
	return err
}

// ReserveIssue atomically reserves a slot before making the external request.
func (s *Store) ReserveIssue(ctx context.Context, repo string, now time.Time, digest bool) (bool, error) {
	tx, err := s.errorsDB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	var hour, day, regularHour, regularDay int
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(SUM(created_at>?),0),COUNT(*),COALESCE(SUM(created_at>? AND digest=0),0),COALESCE(SUM(digest=0),0) FROM issue_budget WHERE repo=? AND created_at>?`, now.Add(-time.Hour).Unix(), now.Add(-time.Hour).Unix(), repo, now.Add(-24*time.Hour).Unix()).Scan(&hour, &day, &regularHour, &regularDay)
	if err != nil {
		return false, err
	}
	if hour >= 5 || day >= 20 || (!digest && (regularHour >= 4 || regularDay >= 19)) {
		return false, nil
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO issue_budget VALUES(?,?,?)`, repo, now.Unix(), digest); err != nil {
		return false, err
	}
	return true, tx.Commit()
}
func (s *Store) ReleaseIssue(ctx context.Context, repo string, now time.Time, digest bool) error {
	_, err := s.errorsDB.ExecContext(ctx, `DELETE FROM issue_budget WHERE rowid=(SELECT rowid FROM issue_budget WHERE repo=? AND created_at=? AND digest=? LIMIT 1)`, repo, now.Unix(), digest)
	return err
}
