package store

import (
	"context"
	"time"
)

const DiskAlertMachineHourlyBudget = 20
const DiskAlertGlobalHourlyBudget = 200

// Reserve persists attempt budgets and an in-flight lease before delivery. A
// failed send releases the condition cooldown, retaining its hourly attempt cost;
// an unknown outcome conservatively holds the full cooldown across restarts.
// the notifier's existing per-episode retry backoff still applies.
func (s *Store) ReserveDiskAlertDelivery(machine, key, lane string, now time.Time) (int64, error) {
	tx, err := s.beginWrite(context.Background(), "disk_alert_delivery_reserve")
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	window := 24 * time.Hour
	if lane == "critical" {
		window = 6 * time.Hour
	}
	var count int
	err = tx.QueryRow(`SELECT COUNT(*) FROM disk_alert_delivery_reservations WHERE machine_id=? AND condition_key=? AND lane=? AND (delivered=1 OR completed=0) AND reserved_at>?`, machine, key, lane, diskReceiptTime(now.Add(-window))).Scan(&count)
	if err != nil || count > 0 {
		return 0, err
	}
	if lane == "recovery" {
		if err = tx.QueryRow(`SELECT COUNT(*) FROM disk_alerts WHERE machine_id=? AND condition_key=? AND cleared_at IS NULL`, machine, key).Scan(&count); err != nil || count > 0 {
			return 0, err
		}
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM disk_alert_delivery_reservations WHERE reserved_at>?`, diskReceiptTime(now.Add(-time.Hour))).Scan(&count); err != nil || count >= DiskAlertGlobalHourlyBudget {
		return 0, err
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM disk_alert_delivery_reservations WHERE machine_id=? AND reserved_at>?`, machine, diskReceiptTime(now.Add(-time.Hour))).Scan(&count); err != nil || count >= DiskAlertMachineHourlyBudget {
		return 0, err
	}
	result, err := tx.Exec(`INSERT INTO disk_alert_delivery_reservations(machine_id,condition_key,lane,reserved_at) VALUES (?,?,?,?)`, machine, key, lane, diskReceiptTime(now))
	if err != nil {
		return 0, err
	}
	sequence, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	// Rows needed for throttling last at most 24h; keep 48h for conservative
	// clock boundaries and prune using the indexed Hub reservation timestamp.
	if _, err = tx.Exec(`DELETE FROM disk_alert_delivery_reservations WHERE reserved_at<?`, diskReceiptTime(now.Add(-48*time.Hour))); err != nil {
		return 0, err
	}
	return sequence, tx.Commit()
}
func (s *Store) FinishDiskAlertDelivery(sequence int64, delivered bool) error {
	tx, err := s.beginWrite(context.Background(), "disk_alert_delivery_finish")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`UPDATE disk_alert_delivery_reservations SET completed=1,delivered=? WHERE sequence=? AND completed=0`, delivered, sequence); err != nil {
		return err
	}
	return tx.Commit()
}
