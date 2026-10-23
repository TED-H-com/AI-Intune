package store

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"testing"
	"time"
)

func deepFixture(t *testing.T) (*Store, ScriptRunRequest, time.Time) {
	s, req, now := safeDiskFixture(t)
	var a map[string]string
	_ = json.Unmarshal(req.Args, &a)
	e, _ := scriptcatalog.Lookup("disk-deep-report-v1")
	req.ScriptID = e.ID
	req.ScriptSHA256 = e.SHA256
	req.Args = mustScriptJSON(map[string]any{"policy_id": a["policy_id"], "policy_digest": a["policy_digest"], "max_items": 500})
	s.ConfigureDiskOpsV2Writes(false)
	return s, req, now
}
func deepJob(t *testing.T, s *Store, req ScriptRunRequest, now time.Time) string {
	p, e := s.ScriptRun(req, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	o, e := s.ScriptRun(req, true, "deep-job", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	id := o.JobIDs[0]
	token, e := s.ClaimJob(id, req.Targets[0], now, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.AdvanceJobByAgent(id, req.Targets[0], token, deploy.Start, now); e != nil {
		t.Fatal(e)
	}
	return id
}
func fixtureReport(req ScriptRunRequest) diskreport.Report {
	var a struct {
		ID     string `json:"policy_id"`
		Digest string `json:"policy_digest"`
	}
	_ = json.Unmarshal(req.Args, &a)
	return diskreport.Report{Schema: "disk-deep/v1", PolicyID: a.ID, PolicyDigest: a.Digest, Items: []diskreport.Item{{ID: "candidate-1", Category: "app-update-backups", PrivatePath: "/home/private-account/private-project/archive.bak", AllocatedBytes: 4096, LogicalBytes: 2000, EvidenceStrength: "weak", OwnerApp: "unknown", Confidence: "low", SuggestedAction: "investigate", Identity: diskreport.Identity{Inode: 42, Size: 2000}}}, Excluded: map[string]diskreport.Aggregate{"protected": {Count: 2, AllocatedBytes: 8192}}, Partial: true, Entries: 20}
}
func TestDiskReportUploadBindingReplayLimitsAndRedaction(t *testing.T) {
	s, req, now := deepFixture(t)
	job := deepJob(t, s, req, now)
	report := fixtureReport(req)
	raw := mustScriptJSON(report)
	chunk := diskreport.Chunk{Sequence: 0, Digest: diskreport.Digest(raw), Data: raw}
	if _, e := s.DiskReportChunk("wrong-machine", job, chunk); e == nil {
		t.Fatal("cross-machine upload accepted")
	}
	for _, bad := range []diskreport.Chunk{{Sequence: 1, Digest: chunk.Digest, Data: raw}, {Sequence: 0, Digest: "wrong", Data: raw}, {Sequence: 0, Digest: diskreport.Digest(make([]byte, 65537)), Data: make([]byte, 65537)}} {
		if _, e := s.DiskReportChunk(req.Targets[0], job, bad); e == nil {
			t.Fatal("bad chunk accepted")
		}
	}
	if _, e := s.DiskReportChunk(req.Targets[0], job, chunk); e != nil {
		t.Fatal(e)
	}
	if _, e := s.DiskReportChunk(req.Targets[0], job, chunk); e != nil {
		t.Fatal("retry", e)
	}
	other := chunk
	other.Data = []byte("changed")
	other.Digest = diskreport.Digest(other.Data)
	if _, e := s.DiskReportChunk(req.Targets[0], job, other); e == nil {
		t.Fatal("changed replay accepted")
	}
	complete := diskreport.Complete{Digest: diskreport.Digest(raw), ItemCount: 1}
	bad := complete
	bad.ItemCount = 2
	if _, e := s.DiskReportComplete(req.Targets[0], job, bad); e == nil {
		t.Fatal("wrong item count accepted")
	}
	bad = complete
	bad.Digest = "wrong"
	if _, e := s.DiskReportComplete(req.Targets[0], job, bad); e == nil {
		t.Fatal("wrong digest accepted")
	}
	receipt, e := s.DiskReportComplete(req.Targets[0], job, complete)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.DiskReportComplete(req.Targets[0], job, complete); e != nil {
		t.Fatal(e)
	}
	var lease string
	if e = s.rdb.QueryRow(`SELECT lease_token FROM jobs WHERE job_id=?`, job).Scan(&lease); e != nil {
		t.Fatal(e)
	}
	if e = s.RecordVerification(job, req.Targets[0], lease, scriptcatalog.Kind, req.ScriptID, 0, string(mustScriptJSON(receipt)), "", true, now); e != nil {
		t.Fatal("safe receipt rejected", e)
	}
	var excerpt string
	if e = s.rdb.QueryRow(`SELECT stdout_excerpt FROM verification_results WHERE job_id=?`, job).Scan(&excerpt); e != nil || !strings.Contains(excerpt, receipt.Digest) || !strings.Contains(excerpt, receipt.ID) {
		t.Fatal("receipt digest redacted", excerpt, e)
	}
	page, e := s.DiskReport(receipt.ID, "", 100, false)
	if e != nil {
		t.Fatal(e)
	}
	public := string(mustScriptJSON(page))
	if strings.Contains(public, "private-account") || strings.Contains(public, "private-project") || strings.Contains(public, "private_path") {
		t.Fatal("private path leaked", public)
	}
	private, e := s.DiskReport(receipt.ID, "", 100, true)
	if e != nil || private.Items[0].PrivatePath != report.Items[0].PrivatePath {
		t.Fatal("missing admin path", e)
	}
	var audit string
	if e = s.rdb.QueryRow(`SELECT detail FROM audit_log WHERE action='disk_report_complete'`).Scan(&audit); e != nil || strings.Contains(audit, "/home/") {
		t.Fatal("audit leakage", e)
	}
	for _, limit := range []int{0, 101} {
		if _, e = s.DiskReport(receipt.ID, "", limit, false); e == nil {
			t.Fatal("invalid pagination")
		}
	}
	if e = s.PruneDiskReports(now.Add(31 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DiskReport(receipt.ID, "", 100, false); e == nil {
		t.Fatal("expired report retained")
	}
}
func TestDeepReadHumanOnlyAndCoalescing(t *testing.T) {
	s, req, now := deepFixture(t)
	service := diskAdmin()
	service.AuthMethod = operatorauth.AuthMethodServiceToken
	service.AuthCapability = "operate"
	if _, e := s.ScriptRun(req, false, "", service); e == nil {
		t.Fatal("new token-eligible enqueue")
	}
	_ = deepJob(t, s, req, now)
	if _, e := s.ScriptRun(req, false, "", diskAdmin()); e == nil {
		t.Fatal("active deep job was not coalesced")
	}
}
func TestDiskPressureStrictThresholdFreshnessAndCoalescing(t *testing.T) {
	for _, tc := range []struct {
		name    string
		free    int64
		age     time.Duration
		capable bool
		want    int
	}{{"80 exact", 200, 0, true, 0}, {"above 80", 199, 0, true, 1}, {"stale", 100, 16 * time.Minute, true, 0}, {"15 minute boundary", 100, 15 * time.Minute, true, 1}, {"capability absent", 100, 0, false, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			s, req, now := deepFixture(t)
			c := healthyCheckin(now.Add(time.Second - tc.age))
			c.ScriptV1 = true
			c.DiskOpsV2 = tc.capable
			c.DiskTotalBytes = 1000
			c.DiskFreeBytes = tc.free
			if e := s.RecordCheckin(req.Targets[0], c, now.Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			if e := s.ReconcileDiskPressure(now.Add(time.Second)); e != nil {
				t.Fatal(e)
			}
			var count int
			if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); e != nil || count != tc.want {
				t.Fatalf("jobs=%d want %d: %v", count, tc.want, e)
			}
			if e := s.ReconcileDiskPressure(now.Add(2 * time.Second)); e != nil {
				t.Fatal(e)
			}
			if e := s.ReconcileDiskPressure(now.Add(time.Minute)); e != nil {
				t.Fatal(e)
			}
			_ = s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count)
			if count != tc.want {
				t.Fatal("trigger retry duplicated jobs")
			}
		})
	}
}

func TestDiskReportTotalLimitIncompleteRetentionAndClosedDocument(t *testing.T) {
	s, req, now := deepFixture(t)
	job := deepJob(t, s, req, now)
	block := make([]byte, diskreport.MaxChunk)
	for n := range block {
		block[n] = ' '
	}
	for seq := 0; seq < 32; seq++ {
		if _, e := s.DiskReportChunk(req.Targets[0], job, diskreport.Chunk{Sequence: seq, Digest: diskreport.Digest(block), Data: block}); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.DiskReportChunk(req.Targets[0], job, diskreport.Chunk{Sequence: 32, Digest: diskreport.Digest([]byte("x")), Data: []byte("x")}); e == nil {
		t.Fatal("2 MiB limit bypassed")
	}
	if _, e := s.DiskReportComplete(req.Targets[0], job, diskreport.Complete{Digest: diskreport.Digest(block), ItemCount: 0}); e == nil {
		t.Fatal("invalid JSON finalized")
	}
	if e := s.PruneDiskReports(now.Add(24*time.Hour + time.Second)); e != nil {
		t.Fatal(e)
	}
	var count int
	_ = s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_reports`).Scan(&count)
	if count != 0 {
		t.Fatal("incomplete upload retained")
	}
	_ = s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_report_chunks`).Scan(&count)
	if count != 0 {
		t.Fatal("private chunks retained")
	}
	r := fixtureReport(req)
	for len(r.Items) <= 500 {
		i := r.Items[0]
		i.ID = "item-" + time.Duration(len(r.Items)).String()
		r.Items = append(r.Items, i)
	}
	if _, _, e := diskreport.Decode(mustScriptJSON(r)); e == nil {
		t.Fatal("501 items accepted")
	}
}
func TestDeepWeeklyPressureSixHourSharedSlot(t *testing.T) {
	s, req, now := deepFixture(t)
	var args struct {
		ID     string `json:"policy_id"`
		Digest string `json:"policy_digest"`
	}
	_ = json.Unmarshal(req.Args, &args)
	template, e := DiskDeepScheduleTemplate(args.ID, args.Digest, req.Targets[0], 5, 30)
	if e != nil || template.Cron != "30 5 * * 0" || template.CatchUp {
		t.Fatal(template, e)
	}
	template.Reason = "weekly read inventory"
	preview, e := s.ScheduleManage(template, "upsert", false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	template.PreviewDigest = preview.PreviewDigest
	o, e := s.ScheduleManage(template, "upsert", true, "weekly", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	job := deepJob(t, s, req, now)
	// A terminal scan still occupies the six-hour host slot.
	if _, e = s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(now), job); e != nil {
		t.Fatal(e)
	}
	if _, e = s.runSchedule(o.Schedule.ID, now.Add(6*time.Hour-time.Second), true, diskAdmin(), &ScheduleRunNowResponse{}); e == nil {
		t.Fatal("manual schedule needs retry key")
	}
	available, e := deepAvailableTx(s.rdb, req.Targets[0], now.Add(6*time.Hour-time.Nanosecond))
	if e != nil || available {
		t.Fatal("slot released early", e)
	}
	available, e = deepAvailableTx(s.rdb, req.Targets[0], now.Add(6*time.Hour))
	if e != nil || !available {
		t.Fatal("slot not released at boundary", e)
	}
	c := healthyCheckin(now.Add(6 * time.Hour))
	c.DiskOpsV2 = true
	c.ScriptV1 = true
	c.DiskTotalBytes = 1000
	c.DiskFreeBytes = 100
	if e = s.RecordCheckin(req.Targets[0], c, now.Add(6*time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e = s.ReconcileDiskPressure(now.Add(6 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	var count int
	_ = s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count)
	if count != 2 {
		t.Fatal("pressure did not use weekly policy", count)
	}
}

func TestWeeklyDeepCoalescedSlotIsFinalizedAndAudited(t *testing.T) {
	s, req, now := deepFixture(t)
	var args struct {
		ID     string `json:"policy_id"`
		Digest string `json:"policy_digest"`
	}
	_ = json.Unmarshal(req.Args, &args)
	template, _ := DiskDeepScheduleTemplate(args.ID, args.Digest, req.Targets[0], 5, 30)
	template.Reason = "weekly read inventory"
	p, e := s.ScheduleManage(template, "upsert", false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	template.PreviewDigest = p.PreviewDigest
	o, e := s.ScheduleManage(template, "upsert", true, "weekly", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	_ = deepJob(t, s, req, now)
	if _, e = s.db.Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(now), o.Schedule.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = s.runSchedule(o.Schedule.ID, now, false, AuditEntry{}, nil); e != nil {
		t.Fatal(e)
	}
	var outcome string
	if e = s.rdb.QueryRow(`SELECT outcome FROM schedule_slots WHERE schedule_id=? AND slot=?`, o.Schedule.ID, fmtTime(now)).Scan(&outcome); e != nil || outcome != "skipped_overlap" {
		t.Fatal("unfinalized coalesced slot", outcome, e)
	}
	v, e := s.ScheduleGet(o.Schedule.ID)
	if e != nil || !v.NextRunAt.After(now) {
		t.Fatal("coalesced cron did not advance", e)
	}
}

func TestDiskPressureWriteAmplificationAndLifecycle(t *testing.T) {
	for _, mode := range []string{"below", "unavailable", "stale", "retired", "inactive", "above"} {
		t.Run(mode, func(t *testing.T) {
			s, req, now := deepFixture(t)
			id := req.Targets[0]
			c := healthyCheckin(now)
			c.ScriptV1 = true
			c.DiskOpsV2 = mode != "unavailable"
			c.DiskTotalBytes = 1000
			c.DiskFreeBytes = 100
			if mode == "below" {
				c.DiskFreeBytes = 200
			}
			if mode == "stale" {
				c = healthyCheckin(now.Add(-16 * time.Minute))
				c.ScriptV1 = true
				c.DiskOpsV2 = true
				c.DiskTotalBytes = 1000
				c.DiskFreeBytes = 100
			}
			if err := s.RecordCheckin(id, c, now); err != nil {
				t.Fatal(err)
			}
			if mode == "retired" {
				if err := s.RetireMachine(id, now); err != nil {
					t.Fatal(err)
				}
			}
			if mode == "inactive" {
				if _, err := s.DB().Exec(`UPDATE machine_registry SET expected=0 WHERE machine_id=?`, id); err != nil {
					t.Fatal(err)
				}
			}
			for n := 0; n < 360; n++ {
				at := now.Add(time.Duration(n) * time.Minute)
				// Keep the selected observation fresh throughout six hours.
				if mode != "stale" {
					c.SentAt = at
					if err := s.RecordCheckin(id, c, at); err != nil {
						t.Fatal(err)
					}
				}
				if err := s.ReconcileDiskPressure(at); err != nil {
					t.Fatal(err)
				}
			}
			var slots, audits, jobs int
			if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_deep_trigger_slots`).Scan(&slots); err != nil {
				t.Fatal(err)
			}
			if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='disk_pressure_trigger'`).Scan(&audits); err != nil {
				t.Fatal(err)
			}
			if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&jobs); err != nil {
				t.Fatal(err)
			}
			if mode == "above" {
				if slots != 2 || audits != 2 || jobs != 1 {
					t.Fatalf("six-hour rows slots=%d audits=%d jobs=%d", slots, audits, jobs)
				}
			} else if slots != 0 || audits != 0 || jobs != 0 {
				t.Fatalf("routine rows slots=%d audits=%d jobs=%d", slots, audits, jobs)
			}
		})
	}
}

func TestDiskReportStoresOnlyRawPrivateBindingAndScrubsDisplays(t *testing.T) {
	s, req, now := deepFixture(t)
	job := deepJob(t, s, req, now)
	r := fixtureReport(req)
	path := "/home/example/arch\u202eive\u200b.bak"
	r.Items[0].PrivatePath = path
	raw := mustScriptJSON(r)
	if _, err := s.DiskReportChunk(req.Targets[0], job, diskreport.Chunk{Sequence: 0, Digest: diskreport.Digest(raw), Data: raw}); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.DiskReportComplete(req.Targets[0], job, diskreport.Complete{Digest: diskreport.Digest(raw), ItemCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	var private, body string
	if err = s.rdb.QueryRow(`SELECT private_path,body FROM disk_report_items WHERE report_id=?`, receipt.ID).Scan(&private, &body); err != nil {
		t.Fatal(err)
	}
	var retained int
	if err = s.rdb.QueryRow(`SELECT SUM(length(data)) FROM disk_report_chunks WHERE report_id=?`, receipt.ID).Scan(&retained); err != nil {
		t.Fatal(err)
	}
	if retained != 0 {
		t.Fatal("completed chunks retain raw path copy")
	}
	if private != path || strings.Contains(body, "\u202e") || strings.Contains(body, "\u200b") || strings.Contains(body, "private_path") {
		t.Fatal("private binding/display separation failed", body)
	}
	for _, admin := range []bool{false, true} {
		p, e := s.DiskReport(receipt.ID, "", 100, admin)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(p.Items[0].PrivatePath+p.Items[0].DisplayPath, "\u202e") || strings.Contains(p.Items[0].PrivatePath+p.Items[0].DisplayPath, "\u200b") {
			t.Fatal("unsafe path projection")
		}
	}
}

func TestDiskReportUnauthorizedAndInactiveIDsDoNotAcquireWriter(t *testing.T) {
	s, req, now := deepFixture(t)
	job := deepJob(t, s, req, now)
	s.SetWriterWait(30 * time.Millisecond)
	chunk := diskreport.Chunk{Data: []byte("{}")}
	chunk.Digest = diskreport.Digest(chunk.Data)
	// With a held writer, each of these requests must still return its authority
	// error from the query-only pool, rather than queueing or returning writer busy.
	held, err := s.beginWrite(context.Background(), "hold_report_writer")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	for _, tc := range []struct{ machine, job string }{{req.Targets[0], "arbitrary-job"}, {"other-machine", job}} {
		if _, err = s.DiskReportChunk(tc.machine, tc.job, chunk); err == nil || IsBusy(err) {
			t.Fatalf("chunk precheck: %v", err)
		}
		if _, err = s.DiskReportComplete(tc.machine, tc.job, diskreport.Complete{}); err == nil || IsBusy(err) {
			t.Fatalf("complete precheck: %v", err)
		}
	}
	held.Rollback()
	if _, err = s.DB().Exec(`UPDATE jobs SET lease_expires_at=? WHERE job_id=?`, fmtTime(now.Add(-time.Hour)), job); err != nil {
		t.Fatal(err)
	}
	held, err = s.beginWrite(context.Background(), "hold_inactive_report_writer")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	if _, err = s.DiskReportChunk(req.Targets[0], job, chunk); err == nil || IsBusy(err) {
		t.Fatalf("inactive chunk precheck: %v", err)
	}
	if _, err = s.DiskReportComplete(req.Targets[0], job, diskreport.Complete{}); err == nil || IsBusy(err) {
		t.Fatalf("inactive completion precheck: %v", err)
	}
}

func TestDiskReportUploadRechecksAuthorityInsideWriter(t *testing.T) {
	s, req, now := deepFixture(t)
	job := deepJob(t, s, req, now)
	chunk := diskreport.Chunk{Data: []byte("{}")}
	chunk.Digest = diskreport.Digest(chunk.Data)
	// nowFn's second call happens only after the writer is acquired; expiry valid
	// during the reader check must then be rejected by the transaction check.
	originalNow := s.nowFn
	defer func() { s.nowFn = originalNow }()
	for _, complete := range []bool{false, true} {
		calls := 0
		s.nowFn = func() time.Time {
			calls++
			if calls == 1 {
				return now
			}
			return now.Add(2 * time.Hour)
		}
		var err error
		if complete {
			_, err = s.DiskReportComplete(req.Targets[0], job, diskreport.Complete{})
		} else {
			_, err = s.DiskReportChunk(req.Targets[0], job, chunk)
		}
		if err == nil || calls < 2 {
			t.Fatal("transaction authority was not rechecked", err, calls)
		}
	}
	s.nowFn = originalNow
	var count int
	if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_reports`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed recheck mutated report", count, err)
	}
}

func TestDiskPressureFallbackIgnoresUsagePolicy(t *testing.T) {
	s, req, now := deepFixture(t)
	policy := DefaultUsagePolicy()
	preview, err := UsagePolicyPreviewDigest("usage-default", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.PublishUsagePolicy("usage-default", 0, policy, preview, diskAdmin()); err != nil {
		t.Fatal(err)
	}
	c := healthyCheckin(now.Add(time.Second))
	c.ScriptV1 = true
	c.DiskOpsV2 = true
	c.DiskTotalBytes = 1000
	c.DiskFreeBytes = 199
	if err = s.RecordCheckin(req.Targets[0], c, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = s.ReconcileDiskPressure(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("jobs=%d want 1 with one disk policy and one usage policy", count)
	}
}
