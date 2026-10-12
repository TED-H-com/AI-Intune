package main

import (
	"fmt"
	"github.com/teddashh/AI-Intune/internal/store"
	"time"
)

// Episode-specific kinds reuse the notifications ledger and configured notifier.
func (h *hub) sendDiskAlerts(now time.Time) {
	for _, severity := range []string{"critical", "warn"} {
		after := ""
		for {
			items, err := h.store.DiskAlertNotificationBatchSeverity(after, severity, now)
			if err != nil {
				return
			}
			if len(items) == 0 {
				break
			}
			after = store.DiskAlertNotificationCursor(items[len(items)-1])
			for _, a := range items {
				kind := "disk-alert:" + a.ID
				if a.Severity == "critical" && a.ClearedAt == nil {
					if e := h.store.DiskCriticalDeliveryWarning(a.MachineID, a.ConditionKey, kind, now); e != nil {
						continue
					}
				}
				if a.Severity == "critical" && a.ClearedAt != nil {
					v := 0
					_ = h.store.DiskAlertReading(a.MachineID, "delivery-failed:"+a.ConditionKey, "warn", &v, 50, now)
				}
				interval := time.Duration(0)
				if a.ClearedAt != nil {
					kind += ":recovery"
				} else if a.Severity == "critical" {
					interval = 6 * time.Hour
				}
				stats, e := h.store.NotifyKindStats(kind)
				if e != nil {
					continue
				}
				if stats.HasSuccess && (interval == 0 || now.Sub(stats.LastSuccess) < interval) {
					continue
				}
				if stats.HasAttempt && (!stats.HasSuccess || stats.LastAttempt.After(stats.LastSuccess)) && now.Sub(stats.LastAttempt) < notifyBackoff(int(stats.ConsecutiveFailures)) {
					continue
				}
				state := "open"
				if a.ClearedAt != nil {
					state = "cleared"
				}
				lane := a.Severity
				if a.ClearedAt != nil {
					lane = "recovery"
					original, e := h.store.NotifyKindStats("disk-alert:" + a.ID)
					if e != nil || !original.HasSuccess {
						continue
					}
				}
				var reservation int64
				if h.notifier() != nil {
					reservation, e = h.store.ReserveDiskAlertDelivery(a.MachineID, a.ConditionKey, lane, now)
					if e != nil || reservation == 0 {
						continue
					}
				}
				delivered := h.deliver(kind, fmt.Sprintf("Disk %s %s · machine %s · episode %s · %s\nAuthenticated details: /machines/%s/disk", a.Severity, state, a.MachineID, a.ID, a.ConditionKey, a.MachineID), now)
				if reservation != 0 {
					_ = h.store.FinishDiskAlertDelivery(reservation, delivered)
				}
			}
		}
	}
}
