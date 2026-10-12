package store

import (
	"context"
	"time"
)

// Unknown readings never demonstrate recovery. After 24 hours without a fresh
// measurement, retire the episode explicitly as mount_missing, not recovered.
// Batch size and indexed selection also bound cleanup of legacy fabricated keys.
func (s *Store) ExpireMissingDiskMounts(now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "disk_mount_missing_expiry")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`UPDATE disk_alerts SET cleared_at=?,cleared_reason='mount_missing',below_since=NULL WHERE id IN (SELECT id FROM disk_alerts WHERE cleared_at IS NULL AND condition_key LIKE 'mount:%' AND COALESCE(NULLIF(last_seen_at,''),opened_at)<=? ORDER BY COALESCE(NULLIF(last_seen_at,''),opened_at),id LIMIT 1000)`, fmtTime(now), fmtTime(now.Add(-24*time.Hour)))
	if err != nil {
		return err
	}
	return tx.Commit()
}
