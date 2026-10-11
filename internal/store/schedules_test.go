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
