package store

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

var ErrLoopActivity = errors.New("invalid loop activity")

type LoopPolicy struct {
	Threshold     int `json:"threshold"`
	WindowSeconds int `json:"window_seconds"`
}
type LoopEpisode struct {
	ID               int64   `json:"id"`
	MachineID        string  `json:"machine_id"`
	ProcessSignature string  `json:"process_signature"`
	CallSignature    string  `json:"call_signature"`
	StartedAt        string  `json:"started_at"`
	LastSeenAt       string  `json:"last_seen_at"`
	LastProgress     *string `json:"last_progress"`
	Calls            int64   `json:"calls"`
	Rate             float64 `json:"calls_per_minute"`
	AcknowledgedAt   *string `json:"acknowledged_at"`
	ResolvedAt       *string `json:"resolved_at"`
}

func (s *Store) LoopPolicy() (p LoopPolicy, err error) {
	err = s.rdb.QueryRow(`SELECT threshold,window_seconds FROM loop_policy WHERE id=1`).Scan(&p.Threshold, &p.WindowSeconds)
	return
}
func (s *Store) SetLoopPolicy(p LoopPolicy) error {
	if p.Threshold < 2 || p.Threshold > 100000 || p.WindowSeconds < 60 || p.WindowSeconds > 3600 {
		return ErrLoopActivity
	}
	_, err := s.execWrite(context.Background(), "set_loop_policy", `UPDATE loop_policy SET threshold=?,window_seconds=? WHERE id=1`, p.Threshold, p.WindowSeconds)
	return err
}
func ValidateLoopActivity(items []model.CallActivity) error {
	if len(items) > 64 {
		return ErrLoopActivity
	}
	seen := map[string]bool{}
	for _, a := range items {
		k := a.ProcessSignature + a.CallSignature
		if !validLowerSHA256(a.ProcessSignature) || !validLowerSHA256(a.CallSignature) || a.TotalCalls < 0 || a.TotalCalls > 1000000000000 || a.Progress < 0 || seen[k] {
			return ErrLoopActivity
		}
		seen[k] = true
	}
	return nil
}

// Counters are cumulative for one process/call signature. First reports establish
// a baseline; retransmits never add calls. Only explicit progress resets evidence.
func (s *Store) recordLoopActivityTx(tx dbTx, machine string, items []model.CallActivity, now time.Time) error {
	if len(items) == 0 {
		return nil
	}
	var p LoopPolicy
	if err := tx.QueryRow(`SELECT threshold,window_seconds FROM loop_policy WHERE id=1`).Scan(&p.Threshold, &p.WindowSeconds); err != nil {
		return err
	}
	cutoff := fmtTime(now.Add(-time.Duration(p.WindowSeconds) * time.Second))
	if _, err := tx.Exec(`DELETE FROM loop_samples WHERE received_at<=?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM loop_streams WHERE last_seen_at<?`, fmtTime(now.Add(-24*time.Hour))); err != nil {
		return err
	}
	for _, a := range items {
		var total, progress int64
		var last string
		var lp sql.NullString
		err := tx.QueryRow(`SELECT total,progress,last_seen_at,last_progress FROM loop_streams WHERE machine_id=? AND process=? AND signature=?`, machine, a.ProcessSignature, a.CallSignature).Scan(&total, &progress, &last, &lp)
		if err != nil && err != sql.ErrNoRows {
			return err
		}
		if err == sql.ErrNoRows {
			var n int
			if err = tx.QueryRow(`SELECT count(*) FROM loop_streams WHERE machine_id=?`, machine).Scan(&n); err != nil {
				return err
			}
			if n >= 64 {
				continue
			}
			_, err = tx.Exec(`INSERT INTO loop_streams VALUES(?,?,?,?,?,?,NULL)`, machine, a.ProcessSignature, a.CallSignature, a.TotalCalls, a.Progress, fmtTime(now))
			if err != nil {
				return err
			}
			continue
		}
		if a.TotalCalls < total || a.Progress < progress {
			continue
		} // stale/replayed report
		if !now.After(parseTime(last)) {
			continue
		}
		if a.Progress > progress || last <= cutoff {
			if _, err = tx.Exec(`DELETE FROM loop_samples WHERE machine_id=? AND process=? AND signature=?`, machine, a.ProcessSignature, a.CallSignature); err != nil {
				return err
			}
			if a.Progress > progress {
				lp = sql.NullString{String: fmtTime(now), Valid: true}
				if _, err = tx.Exec(`UPDATE loop_episodes SET resolved_at=?,last_progress=? WHERE machine_id=? AND process=? AND signature=? AND resolved_at IS NULL`, fmtTime(now), fmtTime(now), machine, a.ProcessSignature, a.CallSignature); err != nil {
					return err
				}
			}
		} else if delta := a.TotalCalls - total; delta > 0 {
			if _, err = tx.Exec(`INSERT INTO loop_samples VALUES(?,?,?,?,?) ON CONFLICT(machine_id,process,signature,received_at) DO UPDATE SET calls=calls+excluded.calls`, machine, a.ProcessSignature, a.CallSignature, fmtTime(now.Truncate(time.Second)), delta); err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`UPDATE loop_streams SET total=?,progress=?,last_seen_at=?,last_progress=? WHERE machine_id=? AND process=? AND signature=?`, a.TotalCalls, a.Progress, fmtTime(now), lp, machine, a.ProcessSignature, a.CallSignature); err != nil {
			return err
		}
		var calls int64
		var start sql.NullString
		if err = tx.QueryRow(`SELECT COALESCE(SUM(calls),0),MIN(received_at) FROM loop_samples WHERE machine_id=? AND process=? AND signature=? AND received_at>?`, machine, a.ProcessSignature, a.CallSignature, cutoff).Scan(&calls, &start); err != nil {
			return err
		}
		rate := float64(calls) * 60 / float64(p.WindowSeconds)
		if calls > int64(p.Threshold) {
			_, err = tx.Exec(`INSERT INTO loop_episodes(machine_id,process,signature,started_at,last_seen_at,last_progress,calls,rate) SELECT ?,?,?,?,?,?,?,? WHERE NOT EXISTS(SELECT 1 FROM loop_episodes WHERE machine_id=? AND process=? AND signature=? AND resolved_at IS NULL)`, machine, a.ProcessSignature, a.CallSignature, start.String, fmtTime(now), lp, calls, rate, machine, a.ProcessSignature, a.CallSignature)
			if err != nil {
				return err
			}
		}
		if _, err = tx.Exec(`UPDATE loop_episodes SET last_seen_at=?,last_progress=?,calls=?,rate=? WHERE machine_id=? AND process=? AND signature=? AND resolved_at IS NULL`, fmtTime(now), lp, calls, rate, machine, a.ProcessSignature, a.CallSignature); err != nil {
			return err
		}
	}
	return nil
}
func (s *Store) LoopEpisodes(machine string) ([]LoopEpisode, error) {
	rows, err := s.rdb.Query(`SELECT id,machine_id,process,signature,started_at,last_seen_at,last_progress,calls,rate,acknowledged_at,resolved_at FROM loop_episodes WHERE (?='' OR machine_id=?) ORDER BY (resolved_at IS NULL) DESC,id DESC LIMIT 200`, machine, machine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LoopEpisode{}
	for rows.Next() {
		var a LoopEpisode
		if err = rows.Scan(&a.ID, &a.MachineID, &a.ProcessSignature, &a.CallSignature, &a.StartedAt, &a.LastSeenAt, &a.LastProgress, &a.Calls, &a.Rate, &a.AcknowledgedAt, &a.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s *Store) LoopDecision(id int64, resolve bool, now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "loop_decision")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	column := "acknowledged_at"
	if resolve {
		column = "resolved_at"
	}
	result, err := tx.Exec(`UPDATE loop_episodes SET `+column+`=? WHERE id=? AND resolved_at IS NULL`, fmtTime(now), id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	// Human resolution starts a fresh counting window; continuing loops can reopen.
	if resolve {
		if _, err = tx.Exec(`DELETE FROM loop_samples WHERE (machine_id,process,signature) IN (SELECT machine_id,process,signature FROM loop_episodes WHERE id=?)`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type LoopsRead struct {
	SchemaVersion int           `json:"schema_version"`
	Policy        LoopPolicy    `json:"policy"`
	Items         []LoopEpisode `json:"items"`
	Limit         int           `json:"limit"`
	Coverage      string        `json:"coverage"`
}
