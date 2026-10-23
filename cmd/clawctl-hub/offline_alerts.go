package main

import (
	"context"
	"fmt"
	"log"
	"time"
)

func (h *hub) sendOfflineAlerts(now time.Time) {
	started := time.Now()
	h.sendOfflineAlertsWithClock(now, func() time.Time { return now.Add(time.Since(started)) })
}

func (h *hub) sendOfflineAlertsWithClock(now time.Time, current func() time.Time) {
	// No configured channel means no reservations and no backlog of stale alerts.
	if h.notifier() == nil {
		return
	}
	items, err := h.store.ClaimOfflineAlerts(now)
	if err != nil {
		log.Printf("offline alert sweep failed: %v", err)
		return
	}
	for _, item := range items {
		sendAt := current()
		eligible, err := h.store.OfflineAlertEligible(item, sendAt)
		if err != nil || !eligible {
			_ = h.store.FinishOfflineAlert(item, false)
			continue
		}
		status := "Unreachable"
		if item.Recovery {
			status = "reporting again (stable for 2 minutes)"
		}
		body := fmt.Sprintf("Machine %s: %s\nAuthenticated details: /machines/%s\n", item.MachineID, status, item.MachineID)
		delivered := h.deliver(item.Kind, body, sendAt)
		if err := h.store.FinishOfflineAlert(item, delivered); err != nil {
			log.Printf("offline alert delivery latch failed: %v", err)
		}
	}
}

// Independent from the daily loop: a failing immediate alert cannot delay the
// scheduled daily report or update its external dead-man stamp.
func (h *hub) offlineAlertLoop(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.sendOfflineAlerts(now)
		}
	}
}
