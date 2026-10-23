package store

import (
	"context"
	"fmt"
	"runtime"
	"time"
)

// SetObservationUnchangedInterval bounds suppression of identical cli_tool and
// systemd snapshots. Zero (or negative) disables suppression. These kinds feed
// current facts and change comparisons, not report-count history. Heartbeat
// freshness is tracked separately by machine_checkins.
func (s *Store) SetObservationUnchangedInterval(interval time.Duration) {
	s.unchangedInterval.Store(int64(interval))
}

// Keyset pagination limits each writer transaction to 2000 groups. The trigger
// handles concurrent inserts; the tuple comparison makes retries harmless.
func (s *Store) backfillObservedLatest() error {
	var machine, kind, subject string
	for {
		tx, err := s.beginWrite(context.Background(), "backfill_observed_latest")
		if err != nil {
			return err
		}
		rows, err := tx.Query(`SELECT machine_id,kind,subject FROM observed_state
   WHERE (machine_id,kind,subject) > (?,?,?)
   GROUP BY machine_id,kind,subject ORDER BY machine_id,kind,subject LIMIT 2000`, machine, kind, subject)
		if err != nil {
			tx.Rollback()
			return err
		}
		type key struct{ m, k, s string }
		var keys []key
		for rows.Next() {
			var k key
			if err = rows.Scan(&k.m, &k.k, &k.s); err != nil {
				break
			}
			keys = append(keys, k)
		}
		if err == nil {
			err = rows.Err()
		}
		rows.Close()
		if err != nil {
			tx.Rollback()
			return err
		}
		for _, k := range keys {
			_, err = tx.Exec(`INSERT INTO observed_latest
    (machine_id,kind,subject,observation_id,measured_at,received_at,payload,source,observation_sequence)
    SELECT machine_id,kind,subject,observation_id,measured_at,received_at,payload,source,rowid
    FROM (SELECT *,rowid FROM observed_state WHERE machine_id=? AND kind=? AND subject=?
    ORDER BY received_at DESC,measured_at DESC,rowid DESC LIMIT 1) WHERE true
    ON CONFLICT(machine_id,kind,subject) DO UPDATE SET
    observation_id=excluded.observation_id,measured_at=excluded.measured_at,
    received_at=excluded.received_at,payload=excluded.payload,source=excluded.source,
    observation_sequence=excluded.observation_sequence
    WHERE (excluded.received_at,excluded.measured_at,excluded.observation_sequence)>
    (observed_latest.received_at,observed_latest.measured_at,observed_latest.observation_sequence)`, k.m, k.k, k.s)
			if err != nil {
				tx.Rollback()
				return fmt.Errorf("backfill observed latest: %w", err)
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
		if len(keys) < 2000 {
			return nil
		}
		last := keys[len(keys)-1]
		machine, kind, subject = last.m, last.k, last.s
		runtime.Gosched()
	}
}

// Only groups whose latest row is beyond the evaluation instant need history.
const latestBySubjectCurrentSQL = `
SELECT subject,payload,measured_at,received_at FROM observed_latest
 WHERE machine_id=? AND kind=? AND received_at<=?
UNION ALL
SELECT o.subject,o.payload,o.measured_at,o.received_at FROM observed_state o
 WHERE o.rowid IN (
 SELECT (SELECT h.rowid FROM observed_state h
 WHERE h.machine_id=l.machine_id AND h.kind=l.kind AND h.subject=l.subject AND h.received_at<=?
 ORDER BY h.received_at DESC,h.measured_at DESC,h.rowid DESC LIMIT 1)
 FROM observed_latest l WHERE l.machine_id=? AND l.kind=? AND l.received_at>?)
ORDER BY subject ASC`
