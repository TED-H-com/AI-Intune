package store

import (
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"sync"
	"testing"
	"time"
)

func createTestSchedule(t *testing.T) (*Store, Schedule, AuditEntry, time.Time) {
	t.Helper()
	s, r, a, now := scriptFixture(t)
	req := ScheduleRequest{Name: "probe-check", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args, Targets: r.Targets, Cron: "*/5 * * * *", Enabled: true, Reason: r.Reason}
	p, e := s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	out, e := s.ScheduleManage(req, "upsert", true, "schedule-create", a)
	if e != nil {
		t.Fatal(e)
	}
	return s, out.Schedule, a, now
}
func TestScheduleOverlapAndAudit(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	if e := s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, e := s.ScheduleGet(v.ID)
	if e != nil || len(got.LastJobIDs) != 1 {
		t.Fatalf("%+v %v", got, e)
	}
	job, err := s.Job(got.LastJobIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	desired, err := s.DesiredState(job.DesiredID)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := scriptcatalog.Decode([]byte(desired.Spec))
	if err != nil || spec.ExecutionMode != "read" {
		t.Fatal("scheduled job did not persist execution mode")
	}

	if e = s.TickSchedules(got.NextRunAt); e != nil {
		t.Fatal(e)
	}
	var outcome string
	if e = s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, v.ID, fmtTime(got.NextRunAt)).Scan(&outcome); e != nil || outcome != "skipped_overlap" {
		t.Fatalf("%s %v", outcome, e)
	}
	var count int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject=? AND action='schedule-run'`, "scheduler:"+v.Name).Scan(&count)
	if count != 2 {
		t.Fatalf("audit count %d", count)
	}
	var name string
	s.rdb.QueryRow(`SELECT schedule_name FROM schedule_jobs WHERE job_id=?`, got.LastJobIDs[0]).Scan(&name)
	if name != v.Name {
		t.Fatal(name)
	}
}
func TestScheduleConcurrentRunners(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	var seq int
	var dbName, path string
	if e := s.DB().QueryRow(`PRAGMA database_list`).Scan(&seq, &dbName, &path); e != nil {
		t.Fatal(e)
	}
	other, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, runner := range []*Store{s, other} {
		wg.Add(1)
		go func(st *Store) { defer wg.Done(); errs <- st.TickSchedules(v.NextRunAt) }(runner)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		if e != nil {
			t.Fatal(e)
		}
	}
	var n int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM schedule_jobs`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}
func TestSchedulePauseAndRestart(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	if e := s.ResumeSchedules(v.NextRunAt.Add(time.Hour)); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	if !got.NextRunAt.After(v.NextRunAt.Add(time.Hour)) {
		t.Fatal("catch-up")
	}
	s.DB().Exec(`UPDATE schedules SET script_sha256=? WHERE id=?`, strings.Repeat("a", 64), v.ID)
	if e := s.TickSchedules(got.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, _ = s.ScheduleGet(v.ID)
	if got.Enabled || got.PausedReason != "script_changed" {
		t.Fatal(got)
	}
	var n int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&n)
	if n != 0 {
		t.Fatal(n)
	}
}
func TestScheduleScopeRevisionAndDigest(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	r := ScheduleRequest{ID: v.ID, ExpectedRevision: v.Revision, Enabled: false, Reason: "pause check"}
	view := a
	view.AuthCapability = "view"
	if _, e := s.ScheduleManage(r, "set-enabled", false, "", view); e == nil {
		t.Fatal("view accepted")
	}
	p, e := s.ScheduleManage(r, "set-enabled", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	r.PreviewDigest = "sha256:" + strings.Repeat("0", 64)
	if _, e = s.ScheduleManage(r, "set-enabled", true, "bad-digest", a); e == nil {
		t.Fatal("digest accepted")
	}
	r.PreviewDigest = p.PreviewDigest
	out, e := s.ScheduleManage(r, "set-enabled", true, "disable", a)
	if e != nil || out.Schedule.Enabled {
		t.Fatal(e)
	}
	replay, e := s.ScheduleManage(r, "set-enabled", true, "disable", a)
	if e != nil || !replay.Replayed {
		t.Fatal(e)
	}
	if _, e = s.ScheduleManage(r, "set-enabled", false, "", a); e == nil {
		t.Fatal("stale revision")
	}
	if _, e = s.ScheduleRunNow(v.ID, "view-run", view); e == nil {
		t.Fatal("view run-now")
	}
}

func TestScheduleRestartReopensDatabase(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	var seq int
	var name, path string
	if e := s.DB().QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	if e := s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	saved, _ := s.ScheduleGet(v.ID)
	other, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer other.Close()
	later := saved.NextRunAt.Add(time.Hour)
	if e = other.ResumeSchedules(later); e != nil {
		t.Fatal(e)
	}
	resumed, _ := other.ScheduleGet(v.ID)
	if !resumed.NextRunAt.After(later) || len(resumed.LastJobIDs) != 1 || resumed.LastJobIDs[0] != saved.LastJobIDs[0] {
		t.Fatal(resumed)
	}
	if e = other.TickSchedules(later); e != nil {
		t.Fatal(e)
	}
	var n int
	other.rdb.QueryRow(`SELECT COUNT(*) FROM schedule_jobs`).Scan(&n)
	if n != 1 {
		t.Fatal(n)
	}
}

func TestScheduleWriteScope(t *testing.T) {
	for _, capability := range []string{"view", "operate", "admin"} {
		e := scriptScope(scriptcatalog.Entry{Mode: "write"}, AuditEntry{AuthCapability: capability})
		if (e == nil) != (capability == "admin") {
			t.Fatalf("write scope %s: %v", capability, e)
		}
	}
}

func TestScheduleReapprovalAndTerminalResume(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	s.DB().Exec(`UPDATE schedules SET script_sha256=? WHERE id=?`, strings.Repeat("a", 64), v.ID)
	if e := s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	paused, _ := s.ScheduleGet(v.ID)
	req := ScheduleRequest{ID: v.ID, Name: v.Name, ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args, Targets: v.Targets, Cron: v.Cron, Enabled: true, ExpectedRevision: paused.Revision, Reason: "approve catalog hash"}
	p, e := s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	out, e := s.ScheduleManage(req, "upsert", true, "reapprove", a)
	if e != nil || out.Schedule.PausedReason != "" || !out.Schedule.Enabled {
		t.Fatal(e)
	}
	if e = s.TickSchedules(out.Schedule.NextRunAt); e != nil {
		t.Fatal(e)
	}
	first, _ := s.ScheduleGet(v.ID)
	if len(first.LastJobIDs) != 1 {
		t.Fatal(first)
	}
	if _, e = s.DB().Exec(`UPDATE jobs SET state='succeeded' WHERE job_id=?`, first.LastJobIDs[0]); e != nil {
		t.Fatal(e)
	}
	if e = s.TickSchedules(first.NextRunAt); e != nil {
		t.Fatal(e)
	}
	second, _ := s.ScheduleGet(v.ID)
	if len(second.LastJobIDs) != 1 || second.LastJobIDs[0] == first.LastJobIDs[0] {
		t.Fatal(second)
	}
}

// Disabled schedules must obey the same fanout limit before they are enabled.
func TestScheduleTargetLimitMatchesScriptRun(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	targets := make([]string, 51)
	for i := range targets {
		targets[i] = fmt.Sprintf("machine-%02d", i)
	}
	base := ScheduleRequest{Name: "target-limit", ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args, Targets: targets, Cron: v.Cron, Reason: "check target bounds"}
	script := ScriptRunRequest{ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args, Targets: targets, Reason: base.Reason}
	if _, _, e := normalizeScript(script); e == nil {
		t.Fatal("script_run accepted 51 targets")
	}
	script.Targets = targets[:50]
	if _, _, e := normalizeScript(script); e != nil {
		t.Fatalf("script_run rejected 50 targets: %v", e)
	}
	valid := base
	valid.Targets = targets[:50]
	if _, e := s.ScheduleManage(valid, "upsert", false, "", a); e != nil {
		t.Fatalf("disabled schedule rejected 50 targets: %v", e)
	}
	for _, update := range []bool{false, true} {
		for _, enabled := range []bool{false, true} {
			for _, apply := range []bool{false, true} {
				req := base
				req.Enabled = enabled
				if update {
					req.ID = v.ID
					req.Name = v.Name
					req.ExpectedRevision = v.Revision
				}
				req.PreviewDigest = "sha256:" + strings.Repeat("0", 64)
				key := fmt.Sprintf("target-limit-%t-%t-%t", update, enabled, apply)
				_, e := s.ScheduleManage(req, "upsert", apply, key, a)
				if e == nil || !strings.Contains(e.Error(), "1 to 50") {
					t.Fatalf("update=%t enabled=%t apply=%t: %v", update, enabled, apply, e)
				}
			}
		}
	}
	got, e := s.ScheduleGet(v.ID)
	if e != nil || got.Revision != v.Revision || len(got.Targets) != len(v.Targets) {
		t.Fatalf("rejected update changed schedule: %+v %v", got, e)
	}
	var count int
	if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM schedules`).Scan(&count); e != nil || count != 1 {
		t.Fatalf("rejected create changed schedules: %d %v", count, e)
	}
}

func TestScheduleManualNamespaceReplayAndCronProgress(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	now := v.NextRunAt
	s.nowFn = func() time.Time { return now }
	first, e := s.ScheduleRunNow(v.ID, "manual-request", a)
	if e != nil || len(first.JobIDs) != 1 {
		t.Fatalf("manual %+v %v", first, e)
	}
	var n int
	if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM schedule_slots`).Scan(&n); e != nil || n != 0 {
		t.Fatalf("manual claimed cron slot %d %v", n, e)
	}
	if e = s.TickSchedules(now.Add(30 * time.Second)); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	if !got.NextRunAt.After(now) {
		t.Fatal("cron wedged")
	}
	s.DB().Exec(`UPDATE jobs SET state='succeeded' WHERE job_id=?`, first.JobIDs[0])
	now = now.Add(2 * time.Minute)
	replay, e := s.ScheduleRunNow(v.ID, "manual-request", a)
	if e != nil || !replay.Replayed || len(replay.JobIDs) != 1 || replay.JobIDs[0] != first.JobIDs[0] {
		t.Fatalf("replay %+v %v", replay, e)
	}
	if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM schedule_jobs`).Scan(&n); e != nil || n != 1 {
		t.Fatalf("duplicate manual jobs %d %v", n, e)
	}
	if _, e = s.ScheduleRunNow(v.ID, "", a); e == nil {
		t.Fatal("missing key accepted")
	}
	other := a
	other.AuthSubject = "another-operator"
	if _, e = s.ScheduleRunNow(v.ID, "manual-request", other); e == nil {
		t.Fatal("other principal replayed receipt")
	}
	// A legacy/preexisting receipt must also advance the pointer on duplicates.
	s.DB().Exec(`INSERT INTO schedule_slots VALUES (?,?,'enqueued')`, v.ID, fmtTime(got.NextRunAt))
	if e = s.TickSchedules(got.NextRunAt); e != nil {
		t.Fatal(e)
	}
	after, _ := s.ScheduleGet(v.ID)
	if !after.NextRunAt.After(got.NextRunAt) {
		t.Fatal("duplicate cron wedged")
	}
}
func TestScheduleSkippedLateAndRestartEvidence(t *testing.T) {
	for _, outcome := range []string{"skipped_late", "skipped_restart"} {
		t.Run(outcome, func(t *testing.T) {
			s, v, _, _ := createTestSchedule(t)
			now := v.NextRunAt.Add(time.Hour)
			var e error
			if outcome == "skipped_late" {
				e = s.TickSchedules(now)
			} else {
				e = s.ResumeSchedules(now)
			}
			if e != nil {
				t.Fatal(e)
			}
			var saved string
			if e = s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, v.ID, fmtTime(v.NextRunAt)).Scan(&saved); e != nil || saved != outcome {
				t.Fatalf("receipt %s %v", saved, e)
			}
			var n int
			if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject=? AND action='schedule-run' AND detail LIKE ?`, "scheduler:"+v.Name, outcome+"%").Scan(&n); e != nil || n != 1 {
				t.Fatalf("audit %d %v", n, e)
			}
			after, _ := s.ScheduleGet(v.ID)
			if !after.NextRunAt.After(now) {
				t.Fatal("skip did not advance")
			}
			if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&n); e != nil || n != 0 {
				t.Fatalf("catch-up jobs %d %v", n, e)
			}
		})
	}
}

func TestScheduleSkippedEvidenceAtomic(t *testing.T) {
	for _, outcome := range []string{"skipped_late", "skipped_restart"} {
		t.Run(outcome, func(t *testing.T) {
			s, v, _, _ := createTestSchedule(t)
			if _, e := s.DB().Exec(`CREATE TRIGGER reject_skip_audit BEFORE INSERT ON audit_log WHEN NEW.action='schedule-run' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); e != nil {
				t.Fatal(e)
			}
			var e error
			if outcome == "skipped_late" {
				e = s.TickSchedules(v.NextRunAt.Add(time.Hour))
			} else {
				e = s.ResumeSchedules(v.NextRunAt.Add(time.Hour))
			}
			if e == nil {
				t.Fatal("audit failure ignored")
			}
			got, _ := s.ScheduleGet(v.ID)
			if !got.NextRunAt.Equal(v.NextRunAt) {
				t.Fatal("pointer committed without audit")
			}
			var n int
			if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM schedule_slots`).Scan(&n); e != nil || n != 0 {
				t.Fatalf("partial receipt %d %v", n, e)
			}
		})
	}
}

func TestScheduleManualHashPauseAuditsInitiator(t *testing.T) {
	for _, hash := range []string{"", strings.Repeat("a", 64)} {
		t.Run(fmt.Sprintf("hash-length-%d", len(hash)), func(t *testing.T) {
			s, v, a, _ := createTestSchedule(t)
			key := "manual-hash-pause"
			if _, e := s.DB().Exec(`UPDATE schedules SET script_sha256=? WHERE id=?`, hash, v.ID); e != nil {
				t.Fatal(e)
			}
			out, e := s.ScheduleRunNow(v.ID, key, a)
			if e != nil || len(out.JobIDs) != 0 {
				t.Fatalf("pause %+v %v", out, e)
			}
			got, _ := s.ScheduleGet(v.ID)
			if got.Enabled || got.PausedReason != "script_changed" {
				t.Fatal(got)
			}
			var n int
			if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='schedule-run-now' AND auth_subject=? AND subject=? AND idempotency_key=? AND outcome='ok'`, a.AuthSubject, v.Name, key).Scan(&n); e != nil || n != 1 {
				t.Fatalf("initiator audit %d %v", n, e)
			}
			if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='schedule-run' AND auth_subject=? AND detail='script_changed'`, "scheduler:"+v.Name).Scan(&n); e != nil || n != 1 {
				t.Fatalf("scheduler audit %d %v", n, e)
			}
			replay, e := s.ScheduleRunNow(v.ID, key, a)
			if e != nil || !replay.Replayed {
				t.Fatalf("pause replay %+v %v", replay, e)
			}
		})
	}
}
func TestScheduleManualPauseRequiresInitiatorAudit(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	s.DB().Exec(`UPDATE schedules SET script_sha256='' WHERE id=?`, v.ID)
	if _, e := s.DB().Exec(`CREATE TRIGGER reject_manual_audit BEFORE INSERT ON audit_log WHEN NEW.action='schedule-run-now' AND NEW.outcome='ok' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ScheduleRunNow(v.ID, "manual-failed-audit", a); e == nil {
		t.Fatal("pause without initiator audit")
	}
	got, _ := s.ScheduleGet(v.ID)
	if !got.Enabled || got.PausedReason != "" || got.Revision != v.Revision {
		t.Fatal("pause partially committed")
	}
}

func TestBATReportScheduleRequiresAdmin(t *testing.T) {
	st, script, actor, _ := scriptFixture(t)
	entry, _ := scriptcatalog.Lookup("bat-sweep-report-v1")
	req := ScheduleRequest{Name: "bat-report", ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: json.RawMessage(`{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `"}`), Targets: script.Targets, Cron: "17 * * * *", Enabled: false, Reason: "report pilot"}
	if _, err := st.ScheduleManage(req, "upsert", false, "", actor); err == nil {
		t.Fatal("operate scheduled admin-approved connector")
	}
	actor.AuthCapability = "admin"
	preview, err := st.ScheduleManage(req, "upsert", false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	result, err := st.ScheduleManage(req, "upsert", true, "bat-schedule", actor)
	if err != nil {
		t.Fatal(err)
	}
	actor.AuthCapability = "operate"
	if _, err := st.ScheduleRunNow(result.Schedule.ID, "bat-run-operate", actor); err == nil {
		t.Fatal("operate ran admin-approved connector")
	}
	actor.AuthCapability = "admin"
	if run, err := st.ScheduleRunNow(result.Schedule.ID, "bat-run-admin", actor); err != nil || len(run.JobIDs) != 1 {
		t.Fatalf("admin run %+v %v", run, err)
	}
}

func TestScheduleExecutionModePauseAndReapproval(t *testing.T) {
	for _, tc := range []struct {
		name, mode   string
		reclassified bool
	}{
		{"legacy missing approved mode", "", false},
		{"same-hash read to write reclassification", "read", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, v, actor, _ := createTestSchedule(t)
			if tc.reclassified {
				entry, _ := scriptcatalog.Lookup("bat-sweep-report-v1")
				// Reconstruct a read-approved schedule after the same ID/hash
				// has become write in the current catalog.
				if _, err := s.DB().Exec(`UPDATE schedules SET script_id=?,script_sha256=?,execution_mode=? WHERE id=?`, entry.ID, entry.SHA256, tc.mode, v.ID); err != nil {
					t.Fatal(err)
				}
			} else if _, err := s.DB().Exec(`UPDATE schedules SET execution_mode='' WHERE id=?`, v.ID); err != nil {
				t.Fatal(err)
			}
			if err := s.TickSchedules(v.NextRunAt); err != nil {
				t.Fatal(err)
			}
			paused, err := s.ScheduleGet(v.ID)
			if err != nil {
				t.Fatal(err)
			}
			if paused.Enabled || paused.PausedReason != "mode_changed" || paused.Revision != v.Revision+1 {
				t.Fatal("mode drift not paused")
			}
			var jobs, audits int
			if err := s.DB().QueryRow(`SELECT COUNT(*) FROM schedule_jobs WHERE schedule_id=?`, v.ID).Scan(&jobs); err != nil || jobs != 0 {
				t.Fatalf("unauthorized jobs=%d err=%v", jobs, err)
			}
			if err := s.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='schedule-run' AND subject=? AND auth_subject=? AND detail='mode_changed'`, v.Name, "scheduler:"+v.Name).Scan(&audits); err != nil || audits != 1 {
				t.Fatalf("pause audit=%d err=%v", audits, err)
			}
			actor.AuthCapability = "admin"
			if _, err := s.ScheduleManage(ScheduleRequest{ID: v.ID, Enabled: true, ExpectedRevision: paused.Revision, Reason: "enable schedule"}, "set-enabled", false, "", actor); err == nil {
				t.Fatal("mode pause bypassed by enabling")
			}
			read, _ := scriptcatalog.Lookup("fleet-probe-v1")
			req := ScheduleRequest{ID: v.ID, Name: v.Name, ScriptID: read.ID, ScriptSHA256: read.SHA256, Args: json.RawMessage(`{}`), Targets: v.Targets, Cron: v.Cron, Enabled: true, ExpectedRevision: paused.Revision, Reason: "reapprove mode"}
			preview, err := s.ScheduleManage(req, "upsert", false, "", actor)
			if err != nil {
				t.Fatal(err)
			}
			req.PreviewDigest = preview.PreviewDigest
			approved, err := s.ScheduleManage(req, "upsert", true, "reapprove-mode", actor)
			if err != nil {
				t.Fatal(err)
			}
			if approved.Schedule.ExecutionMode != "read" || approved.Schedule.PausedReason != "" || !approved.Schedule.Enabled {
				t.Fatal("mode reapproval not persisted")
			}
			if err := s.TickSchedules(approved.Schedule.NextRunAt); err != nil {
				t.Fatal(err)
			}
			after, err := s.ScheduleGet(v.ID)
			if err != nil || len(after.LastJobIDs) != 1 {
				t.Fatal("reapproved schedule did not run")
			}
		})
	}
}

func TestScheduleExecutionModeAdditiveMigration(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	if _, err := s.DB().Exec(`ALTER TABLE schedules DROP COLUMN execution_mode`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := addMissingColumns(s.DB()); err != nil {
			t.Fatal(err)
		}
	}
	legacy, err := s.ScheduleGet(v.ID)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.ExecutionMode != "" || !legacy.Enabled {
		t.Fatal("migration inferred approval mode")
	}
	if err := s.TickSchedules(v.NextRunAt); err != nil {
		t.Fatal(err)
	}
	paused, err := s.ScheduleGet(v.ID)
	if err != nil || paused.Enabled || paused.PausedReason != "mode_changed" {
		t.Fatal("migrated legacy schedule did not fail closed")
	}
}

func TestScheduleManualModePauseIsAtomicAndAudited(t *testing.T) {
	s, v, actor, _ := createTestSchedule(t)
	if _, err := s.DB().Exec(`UPDATE schedules SET execution_mode='' WHERE id=?`, v.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`CREATE TRIGGER reject_mode_audit BEFORE INSERT ON audit_log WHEN NEW.action='schedule-run' AND NEW.detail='mode_changed' BEGIN SELECT RAISE(ABORT,'test audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ScheduleRunNow(v.ID, "failed-mode-pause", actor); err == nil {
		t.Fatal("pause without audit")
	}
	unchanged, err := s.ScheduleGet(v.ID)
	if err != nil || !unchanged.Enabled || unchanged.Revision != v.Revision {
		t.Fatal("pause partially committed")
	}
	if _, err := s.DB().Exec(`DROP TRIGGER reject_mode_audit`); err != nil {
		t.Fatal(err)
	}
	out, err := s.ScheduleRunNow(v.ID, "manual-mode-pause", actor)
	if err != nil || len(out.JobIDs) != 0 {
		t.Fatal("manual mode pause failed")
	}
	replayed, err := s.ScheduleRunNow(v.ID, "manual-mode-pause", actor)
	if err != nil || !replayed.Replayed {
		t.Fatal("mode-pause receipt did not replay")
	}
}

func TestScheduleTimezoneBinding(t *testing.T) {
	s, r, a, _ := scriptFixture(t)
	req := ScheduleRequest{Name: "zone-test", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args, Targets: r.Targets, Cron: "0 12 * * *", TZ: "America/New_York", Enabled: true, Reason: r.Reason}
	preview, err := s.ScheduleManage(req, "upsert", false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	req.TZ = "UTC"
	if _, err = s.ScheduleManage(req, "upsert", true, "wrong-zone", a); err == nil {
		t.Fatal("timezone changed without fresh preview")
	}
	req.TZ = "America/New_York"
	out, err := s.ScheduleManage(req, "upsert", true, "zone-create", a)
	if err != nil {
		t.Fatal(err)
	}
	loc, _ := time.LoadLocation(req.TZ)
	if out.Schedule.NextRunAt.In(loc).Hour() != 12 {
		t.Fatal(out.Schedule.NextRunAt)
	}
	got, err := s.ScheduleGet(out.Schedule.ID)
	if err != nil || got.TZ != req.TZ {
		t.Fatal(got, err)
	}
	req.TZ = "Unknown/Bad"
	if _, err = s.ScheduleManage(req, "upsert", false, "", a); err == nil {
		t.Fatal("invalid timezone accepted")
	}
}

func TestScheduleMigrationTimezoneDefault(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	if v.TZ != "UTC" {
		t.Fatal(v.TZ)
	}
	// Simulate the legacy schema, then reopen through the additive migration.
	var seq int
	var name, path string
	if err := s.DB().QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB().Exec(`ALTER TABLE schedules DROP COLUMN tz`); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	migrated, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer migrated.Close()
	got, err := migrated.ScheduleGet(v.ID)
	if err != nil || got.TZ != "UTC" {
		t.Fatal(got, err)
	}
}

// A job stranded on a machine that left the schedule, or was retired, must not
// hold every later slot in skipped_overlap: nothing will ever claim it.
func TestScheduleOverlapIgnoresDroppedAndRetiredTargets(t *testing.T) {
	s, r, a, now := scriptFixture(t)
	gone := mustEnroll(t, s, "gone-node", now)
	c := healthyCheckin(now)
	c.ScriptV1 = true
	if err := s.RecordCheckin(gone, c, now); err != nil {
		t.Fatal(err)
	}
	keep := r.Targets[0]
	req := ScheduleRequest{Name: "probe-check", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args, Targets: []string{keep, gone}, Cron: "*/5 * * * *", Enabled: true, Reason: r.Reason}
	p, e := s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	out, e := s.ScheduleManage(req, "upsert", true, "schedule-two-targets", a)
	if e != nil {
		t.Fatal(e)
	}
	v := out.Schedule
	if e = s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, e := s.ScheduleGet(v.ID)
	if e != nil || len(got.LastJobIDs) != 2 {
		t.Fatalf("%+v %v", got, e)
	}
	slotOutcome := func(slot time.Time) string {
		t.Helper()
		var outcome string
		if e := s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, v.ID, fmtTime(slot)).Scan(&outcome); e != nil {
			t.Fatal(e)
		}
		return outcome
	}
	// The kept machine finishes; the other machine's job is stranded.
	for _, id := range got.LastJobIDs {
		job, err := s.Job(id)
		if err != nil {
			t.Fatal(err)
		}
		if job.MachineID == keep {
			if _, err := s.DB().Exec(`UPDATE jobs SET state=?,terminal_at=? WHERE job_id=?`, "succeeded", fmtTime(now), id); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Still a target and not retired: the stranded job keeps blocking.
	if e = s.TickSchedules(got.NextRunAt); e != nil {
		t.Fatal(e)
	}
	if o := slotOutcome(got.NextRunAt); o != "skipped_overlap" {
		t.Fatalf("live target outcome %s", o)
	}
	// Retire the stranded machine: its job no longer counts.
	if err := s.RetireMachine(gone, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	// Drop it from the schedule too, as an operator would.
	cur, e := s.ScheduleGet(v.ID)
	if e != nil {
		t.Fatal(e)
	}
	req.ID, req.Targets, req.ExpectedRevision, req.PreviewDigest = v.ID, []string{keep}, cur.Revision, ""
	p, e = s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	if _, e = s.ScheduleManage(req, "upsert", true, "schedule-drop-target", a); e != nil {
		t.Fatal(e)
	}
	fresh := got.NextRunAt.Add(15 * time.Minute)
	if _, e = s.DB().Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(fresh), v.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.TickSchedules(fresh); e != nil {
		t.Fatal(e)
	}
	if o := slotOutcome(fresh); o != "enqueued" {
		t.Fatalf("after drop and retire outcome %s", o)
	}
}

// Dropping a target alone (without retiring it) also releases the slot.
func TestScheduleOverlapIgnoresDroppedTarget(t *testing.T) {
	s, r, a, now := scriptFixture(t)
	gone := mustEnroll(t, s, "gone-node", now)
	c := healthyCheckin(now)
	c.ScriptV1 = true
	if err := s.RecordCheckin(gone, c, now); err != nil {
		t.Fatal(err)
	}
	keep := r.Targets[0]
	req := ScheduleRequest{Name: "probe-check", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args, Targets: []string{keep, gone}, Cron: "*/5 * * * *", Enabled: true, Reason: r.Reason}
	p, e := s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	out, e := s.ScheduleManage(req, "upsert", true, "schedule-two", a)
	if e != nil {
		t.Fatal(e)
	}
	v := out.Schedule
	if e = s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	for _, id := range got.LastJobIDs {
		job, _ := s.Job(id)
		if job.MachineID == keep {
			s.DB().Exec(`UPDATE jobs SET state=?,terminal_at=? WHERE job_id=?`, "succeeded", fmtTime(now), id)
		}
	}
	req.ID, req.Targets, req.ExpectedRevision, req.PreviewDigest = v.ID, []string{keep}, got.Revision, ""
	p, e = s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	if _, e = s.ScheduleManage(req, "upsert", true, "schedule-one", a); e != nil {
		t.Fatal(e)
	}
	fresh := got.NextRunAt.Add(15 * time.Minute)
	if _, e = s.DB().Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(fresh), v.ID); e != nil {
		t.Fatal(e)
	}
	if e = s.TickSchedules(fresh); e != nil {
		t.Fatal(e)
	}
	var outcome string
	if e = s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, v.ID, fmtTime(fresh)).Scan(&outcome); e != nil || outcome != "enqueued" {
		t.Fatalf("%s %v", outcome, e)
	}
}

// A never-claimed scheduled job is rejected once it passes its claim deadline
// (one interval plus grace), with an audit row, so one offline machine cannot
// stall the rest of the fleet. Leased jobs and non-schedule jobs are untouched.
func TestScheduleJobClaimDeadline(t *testing.T) {
	s, r, a, now := scriptFixture(t)
	offline := mustEnroll(t, s, "offline-node", now)
	c := healthyCheckin(now)
	c.ScriptV1 = true
	if err := s.RecordCheckin(offline, c, now); err != nil {
		t.Fatal(err)
	}
	online := r.Targets[0]
	req := ScheduleRequest{Name: "probe-check", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args, Targets: []string{online, offline}, Cron: "*/5 * * * *", Enabled: true, Reason: r.Reason}
	p, e := s.ScheduleManage(req, "upsert", false, "", a)
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	out, e := s.ScheduleManage(req, "upsert", true, "schedule-stale", a)
	if e != nil {
		t.Fatal(e)
	}
	v := out.Schedule
	if e = s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	if len(got.LastJobIDs) != 2 {
		t.Fatalf("%+v", got)
	}
	var stuck string
	for _, id := range got.LastJobIDs {
		j, _ := s.Job(id)
		if j.MachineID == online {
			s.DB().Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(now), id)
		} else {
			stuck = id
		}
	}
	// A job outside any schedule (e.g. a profile assignment) is never swept.
	other := mustEnroll(t, s, "profile-node", now)
	desiredID, revision, err := s.CreateDesiredState("machine", other, "maintenance", "proof", `{"kind":"noop"}`, "test")
	if err != nil {
		t.Fatal(err)
	}
	profileJob, err := s.CreateJob(other, desiredID, revision, NewJob{})
	if err != nil {
		t.Fatal(err)
	}
	s.DB().Exec(`UPDATE jobs SET created_at=? WHERE job_id=?`, fmtTime(now.Add(-48*time.Hour)), profileJob)
	var created string
	s.rdb.QueryRow(`SELECT created_at FROM jobs WHERE job_id=?`, stuck).Scan(&created)
	createdAt, _ := time.Parse(time.RFC3339, created)
	outcomeAt := func(slot time.Time) string {
		t.Helper()
		if _, e := s.DB().Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(slot), v.ID); e != nil {
			t.Fatal(e)
		}
		if e := s.TickSchedules(slot); e != nil {
			t.Fatal(e)
		}
		var o string
		if e := s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, v.ID, fmtTime(slot)).Scan(&o); e != nil {
			t.Fatal(e)
		}
		return o
	}
	state := func(id string) string {
		j, _ := s.Job(id)
		return string(j.State)
	}
	// Unclaimed for one interval: still before its deadline, the next slot is overlap.
	if o := outcomeAt(createdAt.Add(5 * time.Minute).Truncate(time.Minute)); o != "skipped_overlap" || state(stuck) != "not_started" {
		t.Fatalf("one-interval job outcome %s state %s", o, state(stuck))
	}
	// A leased job never expires, however old.
	s.DB().Exec(`UPDATE jobs SET lease_token='lease' WHERE job_id=?`, stuck)
	if o := outcomeAt(createdAt.Add(10 * time.Minute).Truncate(time.Minute)); o != "skipped_overlap" || state(stuck) != "not_started" {
		t.Fatalf("leased job outcome %s state %s", o, state(stuck))
	}
	s.DB().Exec(`UPDATE jobs SET lease_token=NULL WHERE job_id=?`, stuck)
	// Past the deadline: the job is rejected and the run goes ahead on both targets.
	if o := outcomeAt(createdAt.Add(15 * time.Minute).Truncate(time.Minute)); o != "enqueued" {
		t.Fatalf("expired job outcome %s", o)
	}
	if state(stuck) != "rejected" {
		t.Fatalf("stuck job state %s", state(stuck))
	}
	if state(profileJob) != "not_started" {
		t.Fatalf("profile job swept: %s", state(profileJob))
	}
	if after, _ := s.ScheduleGet(v.ID); len(after.LastJobIDs) != 2 {
		t.Fatalf("want two new jobs, got %v", after.LastJobIDs)
	}
	var n int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND outcome='ok' AND machine_id=? AND reason=? AND detail LIKE ?`, string(AuditScheduleJobCancel), offline, ScheduleClaimDeadlineReason, "%"+stuck+"%").Scan(&n)
	if n != 1 {
		t.Fatalf("expiry audit rows %d", n)
	}
}

// Jobs already stuck on a machine that was later dropped from the schedule
// (and of a disabled schedule) are cleared on the first sweep.
func TestScheduleJobClaimDeadlineClearsExistingStuckJobs(t *testing.T) {
	s, v, _, _ := createTestSchedule(t)
	if e := s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	job := got.LastJobIDs[0]
	s.DB().Exec(`UPDATE schedules SET enabled=0,targets='[]' WHERE id=?`, v.ID)
	var created string
	s.rdb.QueryRow(`SELECT created_at FROM jobs WHERE job_id=?`, job).Scan(&created)
	createdAt, _ := time.Parse(time.RFC3339, created)
	if e := s.ExpireScheduleJobs(createdAt.Add(3 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if j, _ := s.Job(job); j.State != "rejected" || j.TerminalAt == nil {
		t.Fatalf("stuck job not expired: %+v", j)
	}
	// A second sweep is a no-op.
	if e := s.ExpireScheduleJobs(createdAt.Add(4 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
}

func TestScheduleStaleCutoffTracksInterval(t *testing.T) {
	now := time.Date(2026, 11, 20, 17, 0, 30, 0, time.UTC)
	daily := scheduleStaleNotStartedCutoff(Schedule{Cron: "0 12 * * *", TZ: "America/New_York"}, now)
	if want := now.Add(-24*time.Hour - scheduleStaleGrace); !daily.Equal(want) {
		t.Fatalf("daily cutoff %s want %s", daily, want)
	}
	// A job made by yesterday's slot still blocks today's slot...
	if made := time.Date(2026, 11, 19, 17, 0, 12, 0, time.UTC); !made.After(daily) {
		t.Fatalf("yesterday's job %s already stale at cutoff %s", made, daily)
	}
	// ...and a job made two slots ago no longer does.
	if made := time.Date(2026, 11, 18, 17, 0, 12, 0, time.UTC); made.After(daily) {
		t.Fatalf("two-day-old job %s not stale at cutoff %s", made, daily)
	}
	if bad := scheduleStaleNotStartedCutoff(Schedule{Cron: "nonsense"}, now); !bad.IsZero() {
		t.Fatal("invalid cron must disable staleness")
	}
}

func TestScheduleJobCancel(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	if e := s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	job := got.LastJobIDs[0]
	a.AuthCapability = "admin"
	if _, e := s.ScheduleJobCancel(job, "", ScheduleJobCancelRequest{Reason: "machine offline"}, a); e == nil {
		t.Fatal("missing idempotency key accepted")
	}
	if _, e := s.ScheduleJobCancel(job, "k0", ScheduleJobCancelRequest{Reason: " "}, a); e == nil {
		t.Fatal("empty reason accepted")
	}
	if _, e := s.ScheduleJobCancel("nope", "k1", ScheduleJobCancelRequest{Reason: "machine offline"}, a); e == nil {
		t.Fatal("unknown job accepted")
	}
	out, e := s.ScheduleJobCancel(job, "k2", ScheduleJobCancelRequest{Reason: "machine offline"}, a)
	if e != nil || out.State != "rejected" || out.ScheduleID != v.ID || out.Replayed {
		t.Fatalf("%+v %v", out, e)
	}
	j, _ := s.Job(job)
	if j.State != "rejected" || j.TerminalAt == nil {
		t.Fatalf("job not terminal: %+v", j)
	}
	again, e := s.ScheduleJobCancel(job, "k2", ScheduleJobCancelRequest{Reason: "machine offline"}, a)
	if e != nil || !again.Replayed || again.JobID != job {
		t.Fatalf("replay %+v %v", again, e)
	}
	if _, e := s.ScheduleJobCancel(job, "k2", ScheduleJobCancelRequest{Reason: "different"}, a); e == nil {
		t.Fatal("idempotency conflict accepted")
	}
	if _, e := s.ScheduleJobCancel(job, "k3", ScheduleJobCancelRequest{Reason: "machine offline"}, a); e == nil {
		t.Fatal("cancelled a terminal job twice")
	}
	var n int
	s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND outcome='ok'`, string(AuditScheduleJobCancel)).Scan(&n)
	if n < 1 {
		t.Fatal("no audit row")
	}
	// After cancel, the next slot is free.
	next, _ := s.ScheduleGet(v.ID)
	if e = s.TickSchedules(next.NextRunAt); e != nil {
		t.Fatal(e)
	}
	var o string
	s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, v.ID, fmtTime(next.NextRunAt)).Scan(&o)
	if o != "enqueued" {
		t.Fatalf("after cancel outcome %s", o)
	}
}

func TestScheduleJobCancelRefusesClaimedJob(t *testing.T) {
	s, v, a, _ := createTestSchedule(t)
	if e := s.TickSchedules(v.NextRunAt); e != nil {
		t.Fatal(e)
	}
	got, _ := s.ScheduleGet(v.ID)
	job := got.LastJobIDs[0]
	if _, e := s.DB().Exec(`UPDATE jobs SET state='claimed',lease_token='lease' WHERE job_id=?`, job); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ScheduleJobCancel(job, "k", ScheduleJobCancelRequest{Reason: "machine offline"}, a); e == nil {
		t.Fatal("claimed job cancelled")
	}
	if _, e := s.DB().Exec(`UPDATE jobs SET state='not_started' WHERE job_id=?`, job); e != nil {
		t.Fatal(e)
	}
	if _, e := s.ScheduleJobCancel(job, "k4", ScheduleJobCancelRequest{Reason: "machine offline"}, a); e == nil {
		t.Fatal("leased not_started job cancelled")
	}
}

// A cron that fires every five minutes of one hour and one that fires once at
// the top of that hour share the same next run; only the following runs tell
// them apart.
func TestSchedulePreviewListsUpcomingRunsInTheScheduleTimezone(t *testing.T) {
	s, r, a, _ := scriptFixture(t)
	at := time.Date(2026, 11, 20, 23, 30, 0, 0, time.UTC) // 2026-11-21 07:30 Asia/Taipei, Saturday
	s.nowFn = func() time.Time { return at }
	req := ScheduleRequest{Name: "morning-check", ScriptID: r.ScriptID, ScriptSHA256: r.ScriptSHA256, Args: r.Args,
		Targets: r.Targets, Cron: "*/5 8 * * *", TZ: "Asia/Taipei", Enabled: true, Reason: r.Reason}
	everyFive, err := s.ScheduleManage(req, "upsert", false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	first := time.Date(2026, 11, 21, 0, 0, 0, 0, time.UTC)
	want := []time.Time{first, first.Add(5 * time.Minute), first.Add(10 * time.Minute), first.Add(15 * time.Minute), first.Add(20 * time.Minute)}
	if fmt.Sprint(everyFive.UpcomingRuns) != fmt.Sprint(want) || !everyFive.Schedule.NextRunAt.Equal(first) {
		t.Fatalf("every five minutes: next=%s runs=%v", everyFive.Schedule.NextRunAt, everyFive.UpcomingRuns)
	}

	req.Cron = "0 8 * * 1-5"
	weekdays, err := s.ScheduleManage(req, "upsert", false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	monday := time.Date(2026, 11, 23, 0, 0, 0, 0, time.UTC)
	want = []time.Time{monday, monday.AddDate(0, 0, 1), monday.AddDate(0, 0, 2), monday.AddDate(0, 0, 3), monday.AddDate(0, 0, 4)}
	if fmt.Sprint(weekdays.UpcomingRuns) != fmt.Sprint(want) || !weekdays.Schedule.NextRunAt.Equal(monday) {
		t.Fatalf("weekdays: next=%s runs=%v", weekdays.Schedule.NextRunAt, weekdays.UpcomingRuns)
	}

	req.PreviewDigest = weekdays.PreviewDigest
	applied, err := s.ScheduleManage(req, "upsert", true, "upcoming-apply", a)
	if err != nil || fmt.Sprint(applied.UpcomingRuns) != fmt.Sprint(want) {
		t.Fatalf("apply runs=%v err=%v", applied.UpcomingRuns, err)
	}
	if _, err = s.DB().Exec(`UPDATE operator_idempotency SET response_json=json_remove(response_json,'$.upcoming_runs') WHERE idempotency_key=?`, "upcoming-apply"); err != nil {
		t.Fatal(err)
	}
	legacy, err := s.ScheduleManage(req, "upsert", true, "upcoming-apply", a)
	if err != nil || !legacy.Replayed || legacy.UpcomingRuns == nil || len(legacy.UpcomingRuns) != 0 {
		t.Fatalf("legacy receipt replay runs=%v replayed=%t err=%v", legacy.UpcomingRuns, legacy.Replayed, err)
	}
	disable := ScheduleRequest{ID: applied.Schedule.ID, ExpectedRevision: applied.Schedule.Revision, Enabled: false, Reason: "pause"}
	disabled, err := s.ScheduleManage(disable, "set-enabled", false, "", a)
	if err != nil || disabled.UpcomingRuns == nil || len(disabled.UpcomingRuns) != 0 {
		t.Fatalf("disabled runs=%v err=%v", disabled.UpcomingRuns, err)
	}
}
