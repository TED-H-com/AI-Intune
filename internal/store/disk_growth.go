package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/diskpolicy"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"time"
)

type DiskGrowthPolicy = diskpolicy.DiskGrowthPolicy

const diskGrowthSchema = `CREATE TABLE IF NOT EXISTS disk_growth_samples(machine_id TEXT NOT NULL,mount TEXT NOT NULL,measured_at TEXT NOT NULL,total INTEGER NOT NULL,available INTEGER NOT NULL,received_at TEXT NOT NULL,PRIMARY KEY(machine_id,mount,measured_at));
CREATE INDEX IF NOT EXISTS disk_growth_sample_age ON disk_growth_samples(received_at);
CREATE TABLE IF NOT EXISTS disk_growth_evidence(machine_id TEXT NOT NULL,mount TEXT NOT NULL,body TEXT NOT NULL,updated_at TEXT NOT NULL,PRIMARY KEY(machine_id,mount));`

type DiskGrowth struct {
	Mount           string    `json:"mount"`
	GBPerHour       float64   `json:"gb_per_hour"`
	WindowMinutes   int       `json:"window_minutes"`
	CoverageMinutes float64   `json:"coverage_minutes"`
	Samples         int       `json:"samples"`
	Known           bool      `json:"known"`
	Sustained       bool      `json:"sustained"`
	TimeToFullHours *float64  `json:"time_to_full_hours,omitempty"`
	MeasuredAt      time.Time `json:"measured_at"`
}

func (s *Store) ConfigureDiskGrowth(p DiskGrowthPolicy) error {
	if !p.Valid() {
		return scriptBad("invalid disk growth defaults")
	}
	s.diskGrowthDefaults.Store(&p)
	return nil
}
func (s *Store) diskGrowthPolicy() DiskGrowthPolicy {
	if p := s.diskGrowthDefaults.Load(); p != nil {
		return *p
	}
	return DiskGrowthPolicy{GBPerHour: 10, WindowMinutes: 30}
}

// Growth requires three distinct observations spanning 80% of the sliding window.
// Every interval must exceed the threshold; cleanup, resize, and gaps reset confidence.
func calculateDiskGrowth(mount string, samples []DiskMountUsage, p DiskGrowthPolicy, now time.Time) DiskGrowth {
	out := DiskGrowth{Mount: mount, WindowMinutes: p.WindowMinutes, Samples: len(samples)}
	if len(samples) < 3 {
		return out
	}
	first, last := samples[0], samples[len(samples)-1]
	start, _ := time.Parse(time.RFC3339Nano, first.MeasuredAt)
	end, _ := time.Parse(time.RFC3339Nano, last.MeasuredAt)
	out.MeasuredAt = end
	out.CoverageMinutes = end.Sub(start).Minutes()
	if end.After(now) || now.Sub(end) > 15*time.Minute || out.CoverageMinutes < float64(p.WindowMinutes)*0.8 {
		return out
	}
	out.Sustained = true
	for i := 1; i < len(samples); i++ {
		a, b := samples[i-1], samples[i]
		at, _ := time.Parse(time.RFC3339Nano, a.MeasuredAt)
		bt, _ := time.Parse(time.RFC3339Nano, b.MeasuredAt)
		hours := bt.Sub(at).Hours()
		if hours <= 0 || hours > float64(p.WindowMinutes)/120 || a.TotalBytes != b.TotalBytes {
			out.Sustained = false
			return out
		}
		rate := float64(a.AvailableBytes-b.AvailableBytes) / 1e9 / hours
		if rate <= float64(p.GBPerHour) {
			out.Sustained = false
		}
	}
	out.Known = true
	out.GBPerHour = float64(first.AvailableBytes-last.AvailableBytes) / 1e9 / end.Sub(start).Hours()
	if out.GBPerHour > 0 {
		hours := float64(last.AvailableBytes) / 1e9 / out.GBPerHour
		out.TimeToFullHours = &hours
	}
	return out
}

func (s *Store) reconcileDiskGrowth(id string, status DiskOpsStatus, now time.Time) error {
	p := s.diskGrowthPolicy()
	policy, err := s.diskCanaryPolicy(id, "user")
	if err != nil {
		return err
	}
	if policy.Growth != nil {
		p = *policy.Growth
	} else if current, e := s.DiskPolicy("disk-default"); e == nil {
		var configured DiskPolicy
		if json.Unmarshal(current.Body, &configured) == nil && configured.Growth != nil {
			p = *configured.Growth
		}
	}
	seen := map[string]bool{}
	for _, mount := range status.Mounts {
		seen["growth:"+scriptcatalog.Digest([]byte(mount.Mount))] = true
		at, e := time.Parse(time.RFC3339Nano, mount.MeasuredAt)
		if e != nil || at.After(now) || now.Sub(at) > 15*time.Minute {
			if err = s.DiskAlertReading(id, "growth:"+scriptcatalog.Digest([]byte(mount.Mount)), "critical", nil, 50, now); err != nil {
				return err
			}
			continue
		}
		if _, err = s.execWrite(context.Background(), "disk_growth_sample", `INSERT OR IGNORE INTO disk_growth_samples VALUES(?,?,?,?,?,?)`, id, mount.Mount, fmtTime(at), mount.TotalBytes, mount.AvailableBytes, fmtTime(now)); err != nil {
			return err
		}
		rows, e := s.rdb.Query(`SELECT total,available,measured_at FROM disk_growth_samples WHERE machine_id=? AND mount=? AND measured_at>=? AND measured_at<=? ORDER BY measured_at`, id, mount.Mount, fmtTime(at.Add(-time.Duration(p.WindowMinutes)*time.Minute)), fmtTime(at))
		if e != nil {
			return e
		}
		samples := []DiskMountUsage{}
		for rows.Next() {
			var m DiskMountUsage
			if e = rows.Scan(&m.TotalBytes, &m.AvailableBytes, &m.MeasuredAt); e != nil {
				rows.Close()
				return e
			}
			samples = append(samples, m)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return e
		}
		g := calculateDiskGrowth(mount.Mount, samples, p, now)
		raw, e := json.Marshal(g)
		if e != nil {
			return e
		}
		if _, err = s.execWrite(context.Background(), "disk_growth_evidence", `INSERT INTO disk_growth_evidence VALUES(?,?,?,?) ON CONFLICT(machine_id,mount) DO UPDATE SET body=excluded.body,updated_at=excluded.updated_at`, id, mount.Mount, string(raw), fmtTime(now)); err != nil {
			return err
		}
		var value *int
		if g.Known {
			v := 0
			if g.Sustained {
				v = 100
			}
			value = &v
		}
		if err = s.DiskAlertReading(id, "growth:"+scriptcatalog.Digest([]byte(mount.Mount)), "critical", value, 50, at); err != nil {
			return err
		}
	}
	for _, a := range status.Alerts {
		if a.ClearedAt == nil && strings.HasPrefix(a.ConditionKey, "growth:") && !seen[a.ConditionKey] {
			if err = s.DiskAlertReading(id, a.ConditionKey, "critical", nil, 50, now); err != nil {
				return err
			}
		}
	}
	return nil
}
func (s *Store) DiskGrowthRead(id string) ([]DiskGrowth, error) {
	out := []DiskGrowth{}
	rows, err := s.rdb.Query(`SELECT body FROM disk_growth_evidence WHERE machine_id=? ORDER BY json_extract(body,'$.gb_per_hour') DESC,mount`, id)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var body string
		if err = rows.Scan(&body); err != nil {
			return out, err
		}
		var g DiskGrowth
		if err = json.Unmarshal([]byte(body), &g); err != nil {
			return out, err
		}
		if s.now().Sub(g.MeasuredAt) > 15*time.Minute {
			g.Known = false
			g.TimeToFullHours = nil
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

func (g DiskGrowth) TimeToFullLabel() string {
	if g.TimeToFullHours == nil {
		return "time-to-full unavailable (no positive growth)"
	}
	return fmt.Sprintf("%.1f hours to full", *g.TimeToFullHours)
}
