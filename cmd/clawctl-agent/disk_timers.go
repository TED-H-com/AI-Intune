package main

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// The fixed show probes are read-only. No sudo or unit mutation is invoked.
func observeDiskTimers(now time.Time) []model.DiskTimerObservation {
	observations := []model.DiskTimerObservation{}
	home, _ := os.UserHomeDir()
	for _, scope := range []string{"user", "root"} {
		o := model.DiskTimerObservation{Scope: scope, ObservedAt: now}
		unit := "disk-clean.timer"
		summary := filepath.Join(home, ".local/state/disk-clean/last.json")
		prefix := []string{"--user"}
		if scope == "root" {
			unit = "disk-clean-root.timer"
			summary = "/var/lib/disk-clean/last.json"
			prefix = nil
		}
		probe := func(unit string) (map[string]string, bool) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			args := append(append([]string{}, prefix...), "show", unit, "--property=LoadState,UnitFileState,ActiveState")
			raw, err := exec.CommandContext(ctx, "systemctl", args...).Output()
			if err != nil || len(raw) > 4096 {
				return nil, false
			}
			m := map[string]string{}
			for _, line := range strings.Split(string(raw), "\n") {
				k, v, ok := strings.Cut(line, "=")
				if ok {
					m[k] = v
				}
			}
			return m, m["LoadState"] != "" && m["ActiveState"] != ""
		}
		m, ok := probe(unit)
		o.Known = ok
		o.Installed = m["LoadState"] == "loaded"
		o.Enabled = m["UnitFileState"] == "enabled" || m["UnitFileState"] == "enabled-runtime"
		o.Active = m["ActiveState"] != "inactive" && m["ActiveState"] != "failed"
		service, known := probe(strings.TrimSuffix(unit, ".timer") + ".service")
		o.Known = o.Known && known
		if scope == "user" {
			weekly, known := probe("disk-clean-weekly.timer")
			o.WeeklyTimer = &model.DiskLocalUnitObservation{Known: known, Installed: weekly["LoadState"] == "loaded", Enabled: weekly["UnitFileState"] == "enabled" || weekly["UnitFileState"] == "enabled-runtime", Active: weekly["ActiveState"] != "inactive" && weekly["ActiveState"] != "failed"}
		}
		o.ServiceActive = service["ActiveState"] != "inactive" && service["ActiveState"] != "failed"
		if f, err := os.Open(summary); err == nil {
			raw, err := io.ReadAll(io.LimitReader(f, 65537))
			f.Close()
			var s struct {
				TS             string `json:"ts"`
				Schema         string `json:"schema"`
				Scope          string `json:"scope"`
				CandidateBytes *int64 `json:"candidate_bytes"`
				Categories     map[string]struct {
					Status string `json:"status"`
					Note   string `json:"note"`
				} `json:"categories"`
			}
			if err == nil && len(raw) <= 65536 && json.Unmarshal(raw, &s) == nil && s.Schema == "fleet-disk-clean/v1" && s.Scope == scope {
				if ts, e := time.Parse(time.RFC3339, s.TS); e == nil && !ts.After(now) {
					age := int64(now.Sub(ts).Seconds())
					o.SummaryAgeSeconds = &age
					o.SummaryAt = ts
					if len(s.Categories) > 0 {
						locked := false
						for _, c := range s.Categories {
							if c.Status == "skipped" && strings.Contains(c.Note, "lock") {
								locked = true
							}
						}
						o.SummaryLockSkipped = &locked
					}
					if s.CandidateBytes != nil && *s.CandidateBytes >= 0 {
						v := *s.CandidateBytes
						o.SummaryCandidateBytes = &v
					}
				}
			}
		}
		observations = append(observations, o)
	}
	return observations
}

func echoDiskTimerTransitions(checkin *model.Checkin, transitions map[string]model.DiskTimerTransition) {
	for i := range checkin.DiskTimers {
		challenge := transitions[checkin.DiskTimers[i].Scope]
		checkin.DiskTimers[i].TransitionRevision = challenge.Revision
		checkin.DiskTimers[i].TransitionNonce = challenge.Nonce
	}
}
