package main

import (
	"testing"
	"time"
)

func TestDiskAlertsImmediateSixHourRepeatAndRecovery(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store, notifyCmd: "cat >/dev/null"}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	v := 93
	if e := f.store.DiskAlertReading(f.machine.id, "mount:fixture:critical", "critical", &v, 93, now); e != nil {
		t.Fatal(e)
	}
	items, _ := f.store.DiskAlertsList("")
	kind := "disk-alert:" + items[0].ID
	h.sendDiskAlerts(now)
	h.sendDiskAlerts(now.Add(time.Minute))
	h.sendDiskAlerts(now.Add(6*time.Hour - time.Second))
	if n := notificationRows(t, h, kind); n != 1 {
		t.Fatal("early repeat", n)
	}
	h.sendDiskAlerts(now.Add(6 * time.Hour))
	if n := notificationRows(t, h, kind); n != 2 {
		t.Fatal("six-hour repeat missing", n)
	}
	v = 90
	if e := f.store.DiskAlertReading(f.machine.id, "mount:fixture:critical", "critical", &v, 93, now.Add(7*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := f.store.DiskAlertReading(f.machine.id, "mount:fixture:critical", "critical", &v, 93, now.Add(7*time.Hour+5*time.Minute)); e != nil {
		t.Fatal(e)
	}
	h.sendDiskAlerts(now.Add(8 * time.Hour))
	h.sendDiskAlerts(now.Add(9 * time.Hour))
	if n := notificationRows(t, h, kind+":recovery"); n != 1 {
		t.Fatal("recovery dedupe", n)
	}
}
func TestDiskWarnAlertsOncePerEpisode(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store, notifyCmd: "cat >/dev/null"}
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	v := 85
	if e := f.store.DiskAlertReading(f.machine.id, "mount:fixture:warn", "warn", &v, 85, now); e != nil {
		t.Fatal(e)
	}
	items, _ := f.store.DiskAlertsList("")
	kind := "disk-alert:" + items[0].ID
	h.sendDiskAlerts(now)
	h.sendDiskAlerts(now.Add(6 * time.Hour))
	h.sendDiskAlerts(now.Add(24 * time.Hour))
	if n := notificationRows(t, h, kind); n != 1 {
		t.Fatal("warning repeated", n)
	}
}

func TestDiskNotificationFlappingUsesStableConditionThrottle(t *testing.T) {
	for _, severity := range []string{"critical", "warn"} {
		t.Run(severity, func(t *testing.T) {
			f := newJobsFixture(t, "example-device")
			h := &hub{store: f.store, notifyCmd: "cat >/dev/null"}
			now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
			key := "mount:flap:" + severity
			threshold := 93
			if severity == "warn" {
				threshold = 85
			}
			high := threshold
			low := threshold - 3
			for i := 0; i < 4; i++ {
				at := now.Add(time.Duration(i) * 10 * time.Minute)
				if e := f.store.DiskAlertReading(f.machine.id, key, severity, &high, threshold, at); e != nil {
					t.Fatal(e)
				}
				h.sendDiskAlerts(at)
				if e := f.store.DiskAlertReading(f.machine.id, key, severity, &low, threshold, at.Add(time.Minute)); e != nil {
					t.Fatal(e)
				}
				if e := f.store.DiskAlertReading(f.machine.id, key, severity, &low, threshold, at.Add(6*time.Minute)); e != nil {
					t.Fatal(e)
				}
				h.sendDiskAlerts(at.Add(7 * time.Minute))
			}
			items, _ := f.store.DiskAlertsList("")
			if len(items) != 4 {
				t.Fatal("episodes discarded", len(items))
			}
			sent := 0
			for _, a := range items {
				stats, e := f.store.NotifyKindStats("disk-alert:" + a.ID)
				if e != nil {
					t.Fatal(e)
				}
				if stats.HasSuccess {
					sent++
				}
			}
			if sent != 1 {
				t.Fatal("flapping generated repeated deliveries", sent)
			}
			window := 6 * time.Hour
			if severity == "warn" {
				window = 24 * time.Hour
			}
			if e := f.store.DiskAlertReading(f.machine.id, key, severity, &high, threshold, now.Add(window)); e != nil {
				t.Fatal(e)
			}
			h.sendDiskAlerts(now.Add(window))
			items, _ = f.store.DiskAlertsList("")
			sent = 0
			for _, a := range items {
				stats, _ := f.store.NotifyKindStats("disk-alert:" + a.ID)
				if stats.HasSuccess {
					sent++
				}
			}
			if sent != 2 {
				t.Fatal("stable cooldown never reopened", sent)
			}
		})
	}
}
