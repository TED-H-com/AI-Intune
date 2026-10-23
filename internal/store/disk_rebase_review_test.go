package store

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/model"
	"strings"
	"testing"
	"time"
)

func TestDiskCleanupTimerEvidenceFailsClosedAtAdmissionAndStart(t *testing.T) {
	cases := []string{"missing", "malformed", "missing-flags", "malformed-time", "unknown", "future", "stale", "invalid-time", "enabled", "active", "service-active", "wrong-scope", "fresh", "boundary"}
	for _, phase := range []string{"admission", "start"} {
		for _, name := range cases {
			t.Run(phase+"/"+name, func(t *testing.T) {
				s, req, now := safeDiskFixture(t)
				machine := req.Targets[0]
				s.nowFn = func() time.Time { return now }
				p, e := s.ScriptRun(req, false, "", diskAdmin())
				if e != nil {
					t.Fatal(e)
				}
				req.PreviewDigest = p.PreviewDigest
				var job, lease string
				if phase == "start" {
					run, e := s.ScriptRun(req, true, "timer-check", diskAdmin())
					if e != nil {
						t.Fatal(e)
					}
					job = run.JobIDs[0]
					lease, e = s.ClaimJob(job, machine, now, time.Hour)
					if e != nil {
						t.Fatal(e)
					}
				}
				o := model.DiskTimerObservation{Scope: "user", Known: true, ObservedAt: now.Add(24 * time.Hour)}
				received := diskReceiptTime(now)
				switch name {
				case "unknown":
					o.Known = false
				case "future":
					received = diskReceiptTime(now.Add(time.Nanosecond))
				case "stale":
					received = diskReceiptTime(now.Add(-15*time.Minute - time.Nanosecond))
				case "invalid-time":
					received = "not-a-time"
				case "enabled":
					o.Enabled = true
				case "active":
					o.Active = true
				case "service-active":
					o.ServiceActive = true
				case "wrong-scope":
					o.Scope = "root"
				case "boundary":
					received = diskReceiptTime(now.Add(-15 * time.Minute))
				}
				raw, _ := json.Marshal(o)
				if name == "malformed" {
					raw = []byte(`{"known":`)
				}
				if name == "malformed-time" {
					raw = []byte(`{"scope":"user","known":true,"enabled":false,"active":false,"service_active":false,"observed_at":"bad-time"}`)
				}
				if name == "missing-flags" {
					raw = []byte(`{"scope":"user","known":true}`)
				}
				if _, e = s.db.Exec(`DELETE FROM disk_timer_observations WHERE machine_id=? AND scope='user'`, machine); e != nil {
					t.Fatal(e)
				}
				if name != "missing" {
					if _, e = s.db.Exec(`INSERT INTO disk_timer_observations(machine_id,scope,observed_at,received_at,body) VALUES (?,'user',?,?,?)`, machine, fmtTime(o.ObservedAt), received, string(raw)); e != nil {
						t.Fatal(e)
					}
				}
				if phase == "admission" {
					_, e = s.ScriptRun(req, true, "timer-check", diskAdmin())
				} else {
					_, e = s.AdvanceJobByAgent(job, machine, lease, deploy.Start, now)
				}
				allowed := name == "fresh" || name == "boundary"
				if (e == nil) != allowed {
					t.Fatalf("%s: admission=%v err=%v", name, allowed, e)
				}
				if !allowed && e != nil && !strings.Contains(e.Error(), "timer") {
					t.Fatal("unrelated rejection", e)
				}
			})
		}
	}
}
func TestDiskStartUsesEventHubTimeForEvidenceAge(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	s.nowFn = func() time.Time { return now }
	p, e := s.ScriptRun(req, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	run, e := s.ScriptRun(req, true, "late-start", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	lease, e := s.ClaimJob(run.JobIDs[0], machine, now, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.AdvanceJobByAgent(run.JobIDs[0], machine, lease, deploy.Start, now.Add(16*time.Minute)); e == nil {
		t.Fatal("stale evidence admitted at delayed Start")
	}
}
func TestDiskAlertNotificationEligibilityAndPriority(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	s.nowFn = func() time.Time { return now }
	closed := fmtTime(now.Add(-time.Hour))
	add := func(id, key, severity string, cleared any) {
		t.Helper()
		if _, e := s.db.Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,cleared_at,last_reading) VALUES (?,?,?,?,?,?,?)`, id, machine, key, severity, fmtTime(now.Add(-2*time.Hour)), cleared, fmtTime(now)); e != nil {
			t.Fatal(e)
		}
	}
	sent := func(id string, at time.Time) {
		t.Helper()
		if e := s.RecordNotification("disk-alert:"+id, "fixture", "safe body", true, "", at); e != nil {
			t.Fatal(e)
		}
	}
	add("z-critical", "crit-due", "critical", nil)
	add("a-warning", "warn-due", "warn", nil)
	add("warn-done", "warn-done", "warn", nil)
	sent("warn-done", now)
	add("critical-recent", "crit-recent", "critical", nil)
	sent("critical-recent", now.Add(-time.Hour))
	add("critical-repeat", "crit-repeat", "critical", nil)
	sent("critical-repeat", now.Add(-6*time.Hour))
	add("closed-done", "closed-done", "warn", closed)
	sent("closed-done", now)
	sent("closed-done:recovery", now)
	add("closed-unsent", "closed-unsent", "warn", closed)
	add("closed-recovery", "closed-recovery", "warn", closed)
	sent("closed-recovery", now)
	rows, e := s.DiskAlertNotificationBatchSeverity("", "", now)
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for _, a := range rows {
		ids = append(ids, a.ID)
	}
	if strings.Join(ids, ",") != "critical-repeat,z-critical,a-warning,closed-recovery" {
		t.Fatal("eligibility/priority", ids)
	}
	rest, e := s.DiskAlertNotificationBatchSeverity(DiskAlertNotificationCursor(rows[1]), "", now)
	if e != nil || len(rest) != 2 || rest[0].ID != "a-warning" || rest[1].ID != "closed-recovery" {
		t.Fatal("priority cursor skipped recovery", rest, e)
	}
	// Hundreds of delivered history rows cannot occupy or paginate the queue.
	for i := 0; i < 150; i++ {
		id := "history-" + time.Unix(int64(i), 0).Format("150405")
		add(id, id, "warn", closed)
		sent(id, now)
		sent(id+":recovery", now)
	}
	rows, e = s.DiskAlertNotificationBatchSeverity("", "", now)
	if e != nil || len(rows) != 4 {
		t.Fatal("completed history leaked into queue", len(rows), e)
	}
}
func TestDiskAlertClearedRetentionPreservesOpenAndBoundary(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	for _, test := range []struct {
		id      string
		cleared any
	}{{"old", fmtTime(now.Add(-91 * 24 * time.Hour))}, {"boundary", fmtTime(now.Add(-90 * 24 * time.Hour))}, {"open", nil}} {
		if _, e := s.db.Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,cleared_at,last_reading) VALUES (?,?,?,'critical',?,?,?)`, test.id, machine, test.id, fmtTime(now.Add(-100*24*time.Hour)), test.cleared, fmtTime(now)); e != nil {
			t.Fatal(e)
		}
	}
	if e := s.PruneDiskAlerts(now); e != nil {
		t.Fatal(e)
	}
	var n int
	for _, id := range []string{"boundary", "open"} {
		if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_alerts WHERE id=?`, id).Scan(&n); e != nil || n != 1 {
			t.Fatal(id, n, e)
		}
	}
	if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_alerts WHERE id='old'`).Scan(&n); e != nil || n != 0 {
		t.Fatal(n, e)
	}
	if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='disk_alert_cleared_retention'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("retention index missing", n, e)
	}
}
