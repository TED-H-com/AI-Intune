package store

import (
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
	if _, e = s.ScheduleRunNow(v.ID, view); e == nil {
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
