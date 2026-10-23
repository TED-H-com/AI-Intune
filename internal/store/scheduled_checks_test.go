package store

import (
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
)

func TestScheduledChecksLatestSlot(t *testing.T) {
	for _, tc := range []struct {
		name                  string
		state                 deploy.JobState
		run, skipped, nextDue bool
		want                  string
	}{
		{"failed", deploy.Failed, true, false, false, "failed"},
		{"rejected", deploy.Rejected, true, false, false, "failed"},
		{"expired", deploy.LeaseExpired, true, false, false, "failed"},
		{"passed", deploy.Succeeded, true, false, false, "passed"},
		{"pending", deploy.NotStarted, true, false, false, "pending"},
		{"never ran", "", false, false, false, "not_run"},
		{"restart skipped", "", false, true, false, "not_run"},
		{"missed after success", deploy.Succeeded, true, false, true, "not_run"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, v, _, _ := createTestSchedule(t)
			at := v.NextRunAt
			if tc.skipped {
				if err := s.ResumeSchedules(at.Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			}
			if tc.run {
				if err := s.TickSchedules(at); err != nil {
					t.Fatal(err)
				}
				v, _ = s.ScheduleGet(v.ID)
				job := v.LastJobIDs[0]
				if _, err := s.db.Exec(`UPDATE jobs SET state=?,terminal_at=? WHERE job_id=?`, tc.state, fmtTime(at.Add(time.Second)), job); err != nil {
					t.Fatal(err)
				}
				if tc.want == "failed" {
					if _, err := s.db.Exec(`INSERT INTO verification_results(verification_id,job_id,machine_id,rule_id,command,exit_code,stderr_excerpt,passed,verified_at) VALUES ('failure',?,?, 'script_v1','',1,?,0,?)`, job, v.Targets[0], "create private script directory\nsecond line", fmtTime(at)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if tc.nextDue {
				at = v.NextRunAt
			}
			got, err := s.ScheduledChecks(at.Add(-time.Minute), at.Add(time.Minute), true)
			if err != nil || len(got) != 1 || len(got[0].Targets) != 1 {
				t.Fatalf("summary: %v %v", got, err)
			}
			r := got[0].Targets[0]
			if r.Status != tc.want || !r.InWindow {
				t.Fatalf("result: %+v", r)
			}
			if tc.want == "failed" && r.Reason != "create private script directory" {
				t.Fatalf("reason: %q", r.Reason)
			}
			if tc.nextDue && !r.At.Equal(at) {
				t.Fatalf("stale success replaced missed slot: %+v", r)
			}
		})
	}
}

func TestScheduledChecksDailyStreakAndManualIsolation(t *testing.T) {
	s, v, a, now := createTestSchedule(t)
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(now.Year(), now.Month(), now.Day()+1, 12, 0, 0, 0, loc).UTC()
	if _, err := s.db.Exec(`UPDATE schedules SET cron='0 12 * * *',tz='America/New_York',next_run_at=? WHERE id=?`, fmtTime(first), v.ID); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		at := first.In(loc).AddDate(0, 0, i).UTC()
		if err := s.TickSchedules(at); err != nil {
			t.Fatal(err)
		}
		current, err := s.ScheduleGet(v.ID)
		if err != nil {
			t.Fatal(err)
		}
		if len(current.LastJobIDs) != 1 {
			t.Fatal("no scheduled job")
		}
		if _, err := s.db.Exec(`UPDATE jobs SET state='failed',terminal_at=? WHERE job_id=?`, fmtTime(at.Add(time.Second)), current.LastJobIDs[0]); err != nil {
			t.Fatal(err)
		}
	}
	// A successful manual retry does not erase five failed scheduled checks.
	manual, err := s.ScheduleRunNow(v.ID, "manual-success", a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(first.Add(5*24*time.Hour)), manual.JobIDs[0]); err != nil {
		t.Fatal(err)
	}
	end := first.In(loc).AddDate(0, 0, 4).Add(time.Minute).UTC()
	got, err := s.ScheduledChecks(end.Add(-24*time.Hour), end, true)
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	if r := got[0].Targets[0]; r.Status != "failed" || r.ConsecutiveFailures != 5 {
		t.Fatalf("streak: %+v", r)
	}
	// Disabled schedules do not contribute to the report but retain UI history.
	if _, err := s.db.Exec(`UPDATE schedules SET enabled=0 WHERE id=?`, v.ID); err != nil {
		t.Fatal(err)
	}
	got, err = s.ScheduledChecks(end.Add(-24*time.Hour), end, true)
	if err != nil || len(got) != 0 {
		t.Fatalf("disabled: %v %v", got, err)
	}
	got, err = s.ScheduledChecks(end.Add(-24*time.Hour), end, false)
	if err != nil || len(got) != 1 || got[0].Targets[0].Status != "failed" {
		t.Fatalf("disabled history: %v %v", got, err)
	}
}

func TestScheduleCoverageExcludesMonitorOnlyAndNonreporting(t *testing.T) {
	s, v, _, now := createTestSchedule(t)
	for _, tc := range []struct {
		name           string
		enabled        *bool
		stale, retired bool
	}{
		{"new worker", boolPointer(true), false, false},
		{"monitor only", boolPointer(false), false, false},
		{"unknown jobs", nil, false, false},
		{"stale worker", boolPointer(true), true, false},
		{"retired worker", boolPointer(true), false, true},
	} {
		id := mustEnroll(t, s, tc.name, now)
		at := now
		if tc.stale {
			at = now.Add(-24 * time.Hour)
		}
		c := healthyCheckin(at)
		c.JobsEnabled = tc.enabled
		if err := s.RecordCheckin(id, c, at); err != nil {
			t.Fatal(err)
		}
		if tc.retired {
			if err := s.RetireMachine(id, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	schedules, err := s.ScheduledChecks(now.Add(-time.Hour), now, true)
	if err != nil {
		t.Fatal(err)
	}
	ov, err := s.Overview(now)
	if err != nil {
		t.Fatal(err)
	}
	names, err := s.UntargetedScheduleMachines(ov.Machines, schedules, now)
	if err != nil || len(names) != 1 || names[0] != "new worker" {
		t.Fatalf("coverage: %v %v (target %s)", names, err, v.Targets[0])
	}
	// Disabling the only schedule makes its reporting, jobs-enabled target visible.
	if _, err := s.db.Exec(`UPDATE schedules SET enabled=0 WHERE id=?`, v.ID); err != nil {
		t.Fatal(err)
	}
	schedules, err = s.ScheduledChecks(now.Add(-time.Hour), now, true)
	if err != nil {
		t.Fatal(err)
	}
	names, err = s.UntargetedScheduleMachines(ov.Machines, schedules, now)
	if err != nil || len(names) != 2 || !strings.Contains(strings.Join(names, ","), "probe-node") {
		t.Fatalf("disabled coverage: %v %v", names, err)
	}
}

func boolPointer(v bool) *bool { return &v }

func TestScheduledChecksRejectionReasonAndEvidenceAuthority(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	at := v.NextRunAt
	if err := s.TickSchedules(at); err != nil {
		t.Fatal(err)
	}
	current, err := s.ScheduleGet(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	job := current.LastJobIDs[0]
	if _, err := s.db.Exec(`UPDATE jobs SET state='rejected',terminal_at=? WHERE job_id=?`, fmtTime(at.Add(time.Second)), job); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO job_events(event_id,job_id,seq,phase,occurred_at,received_at,payload) VALUES ('reject',?,1,'rejected',?,?,?)`, job, fmtTime(at), fmtTime(at), `{"detail":"The installed agent cannot run this check.\nignored line"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO verification_results(verification_id,job_id,machine_id,rule_id,command,stderr_excerpt,passed,verified_at,evidence_role) VALUES ('independent',?,?,'script_v1','','unrelated independent failure',0,?,'independent')`, job, v.Targets[0], fmtTime(at)); err != nil {
		t.Fatal(err)
	}
	got, err := s.ScheduledChecks(at.Add(-time.Minute), at.Add(time.Minute), true)
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	if r := got[0].Targets[0]; r.Status != "failed" || r.Reason != "The installed agent cannot run this check." {
		t.Fatalf("rejection: %+v", r)
	}
}

func TestScheduledChecksDoNotReuseAnotherScriptResult(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	at := v.NextRunAt
	if err := s.TickSchedules(at); err != nil {
		t.Fatal(err)
	}
	current, err := s.ScheduleGet(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(at.Add(time.Second)), current.LastJobIDs[0]); err != nil {
		t.Fatal(err)
	}
	// A schedule edit changes the script; its previous result cannot turn the
	// replacement check green before that script has run.
	if _, err := s.db.Exec(`UPDATE schedules SET script_id='bat-release-check-v1' WHERE id=?`, v.ID); err != nil {
		t.Fatal(err)
	}
	got, err := s.ScheduledChecks(at.Add(-time.Minute), at.Add(time.Minute), true)
	if err != nil || len(got) != 1 {
		t.Fatal(err)
	}
	if r := got[0].Targets[0]; r.Status != "not_run" {
		t.Fatalf("wrong script result: %+v", r)
	}
}
