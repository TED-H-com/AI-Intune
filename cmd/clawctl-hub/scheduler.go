package main

import (
	"context"
	"log"
	"time"
)

func (h *hub) scheduleLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	resumed := h.store.ResumeSchedules(jobNow()) == nil
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !resumed {
				if err := h.store.ResumeSchedules(jobNow()); err != nil {
					log.Print("scheduler resume failed")
					continue
				}
				resumed = true
				continue
			}
			if err := h.store.ReconcileDiskOwnership(jobNow()); err != nil {
				log.Print("disk ownership reconciliation failed")
			}
			if err := h.store.ReconcileDiskAlerts(jobNow()); err != nil {
				log.Print("disk alert reconciliation failed")
			}
			h.sendDiskAlerts(jobNow())
			if err := h.store.ReconcileDiskPressure(jobNow()); err != nil {
				log.Print("disk pressure reconciliation failed")
			}
			if err := h.store.TickSchedules(jobNow()); err != nil {
				log.Print("scheduler tick failed")
			}
		}
	}
}
