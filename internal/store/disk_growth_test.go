package store

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

func TestDiskGrowthMath(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	samples := []DiskMountUsage{}
	for i := 0; i < 4; i++ {
		samples = append(samples, DiskMountUsage{TotalBytes: 100e9, AvailableBytes: 80e9 - int64(i)*2e9, MeasuredAt: now.Add(time.Duration(i-3) * 10 * time.Minute).Format(time.RFC3339)})
	}
	p := DiskGrowthPolicy{GBPerHour: 10, WindowMinutes: 30}
	g := calculateDiskGrowth("/", samples, p, now)
	if !g.Known || !g.Sustained || math.Abs(g.GBPerHour-12) > 0.001 || math.Abs(*g.TimeToFullHours-74.0/12) > 0.001 {
		t.Fatalf("bad growth %+v", g)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]DiskMountUsage) []DiskMountUsage
		stale  bool
	}{
		{"few", func(s []DiskMountUsage) []DiskMountUsage { return s[:2] }, false},
		{"coverage", func(s []DiskMountUsage) []DiskMountUsage { return s[1:] }, false},
		{"resize", func(s []DiskMountUsage) []DiskMountUsage { s[1].TotalBytes++; return s }, false},
		{"duplicate", func(s []DiskMountUsage) []DiskMountUsage { s[1].MeasuredAt = s[0].MeasuredAt; return s }, false},
		{"stale", func(s []DiskMountUsage) []DiskMountUsage { return s }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := append([]DiskMountUsage{}, samples...)
			at := now
			if tc.stale {
				at = at.Add(16 * time.Minute)
			}
			if calculateDiskGrowth("/", tc.mutate(s), p, at).Known {
				t.Fatal("expected unknown")
			}
		})
	}
	samples[2].AvailableBytes = samples[1].AvailableBytes + 1
	if calculateDiskGrowth("/", samples, p, now).Sustained {
		t.Fatal("cleanup must break sustained growth")
	}
	samples[2].AvailableBytes = 76e9
	if calculateDiskGrowth("/", samples, DiskGrowthPolicy{GBPerHour: 12, WindowMinutes: 30}, now).Sustained {
		t.Fatal("equality must not alert")
	}
}

func TestDiskGrowthPolicyAndEpisodes(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	id := req.Targets[0]
	if _, err := s.db.Exec(`DELETE FROM disk_growth_samples WHERE machine_id=?`, id); err != nil {
		t.Fatal(err)
	}
	if s.ConfigureDiskGrowth(DiskGrowthPolicy{GBPerHour: 0, WindowMinutes: 30}) == nil {
		t.Fatal("invalid default accepted")
	}
	if err := s.ConfigureDiskGrowth(DiskGrowthPolicy{GBPerHour: 15, WindowMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	p := DefaultDiskPolicy()
	p.Growth = &DiskGrowthPolicy{GBPerHour: 20, WindowMinutes: 30}
	raw, _ := json.Marshal(p)
	if _, _, _, err := CanonicalDiskPolicy(raw); err != nil {
		t.Fatal(err)
	}
	p.Growth.WindowMinutes = 1
	raw, _ = json.Marshal(p)
	if _, _, _, err := CanonicalDiskPolicy(raw); err == nil {
		t.Fatal("invalid policy accepted")
	}
	for i := 0; i < 4; i++ {
		at := now.Add(time.Duration(i-3) * 10 * time.Minute)
		m := DiskMountUsage{Mount: "/", TotalBytes: 100e9, AvailableBytes: 80e9 - int64(i)*2e9, MeasuredAt: at.Format(time.RFC3339)}
		if err := s.reconcileDiskGrowth(id, DiskOpsStatus{Mounts: []DiskMountUsage{m}}, at); err != nil {
			t.Fatal(err)
		}
	}

	if alerts, err := s.DiskAlertsList(id); err != nil || len(alerts) != 0 {
		t.Fatalf("configured higher threshold should suppress growth: %v", err)
	}
	if err := s.ConfigureDiskGrowth(DiskGrowthPolicy{GBPerHour: 5, WindowMinutes: 30}); err != nil {
		t.Fatal(err)
	}
	m := DiskMountUsage{Mount: "/", TotalBytes: 100e9, AvailableBytes: 74e9, MeasuredAt: now.Format(time.RFC3339)}
	if err := s.reconcileDiskGrowth(id, DiskOpsStatus{Mounts: []DiskMountUsage{m}}, now); err != nil {
		t.Fatal(err)
	}
	alerts, err := s.DiskAlertsList(id)
	if err != nil || len(alerts) != 1 {
		t.Fatalf("episodes %d: %v", len(alerts), err)
	}
	growth, err := s.DiskGrowthRead(id)
	if err != nil || len(growth) != 1 || !growth[0].Sustained {
		t.Fatalf("growth %+v %v", growth, err)
	}
	if err := s.reconcileDiskGrowth(id, DiskOpsStatus{}, now); err != nil {
		t.Fatal(err)
	}
	alerts, _ = s.DiskAlertsList(id)
	if len(alerts) != 1 {
		t.Fatal("duplicate episode")
	}
}
