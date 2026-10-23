package store

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/maintenance"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"testing"
	"time"
)

func safeDiskFixture(t *testing.T) (*Store, ScriptRunRequest, time.Time) {
	s, _, policy, now := diskPolicyFixture(t)
	machine := mustEnroll(t, s, "example-device", now)
	c := healthyCheckin(now)
	c.ScriptV1 = true
	c.DiskOpsV2 = true
	c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, ObservedAt: now}}
	if err := s.RecordCheckin(machine, c, now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`INSERT INTO disk_ownership(machine_id,scope,state,revision,changed_at) VALUES (?,'user','hub-owned',1,?) ON CONFLICT(machine_id,scope) DO UPDATE SET state='hub-owned',revision=1`, machine, fmtTime(now)); err != nil {
		t.Fatal(err)
	}
	entry, _ := scriptcatalog.Lookup("disk-safe-clean-v2")
	return s, ScriptRunRequest{ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: mustScriptJSON(map[string]string{"scope": "user", "policy_id": policy.Policy.ID, "policy_digest": policy.Policy.Digest}), Targets: []string{machine}, Reason: "safe housekeeping"}, now
}
func TestDiskSafeFlagCapabilityPolicyDispatchAndReplay(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	s.ConfigureDiskOpsV2Writes(false)
	preview, err := s.ScriptRun(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	if _, err = s.ScriptRun(req, true, "safe", diskAdmin()); err == nil || !strings.Contains(err.Error(), "disabled") {
		t.Fatal("missing flag gate", err)
	}
	s.ConfigureDiskOpsV2Writes(true)
	c := healthyCheckin(now.Add(time.Second))
	c.ScriptV1 = true
	if err = s.RecordCheckin(req.Targets[0], c, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ScriptRun(req, true, "safe", diskAdmin()); err == nil || !strings.Contains(err.Error(), "disk_ops_v2") {
		t.Fatal("missing capability gate", err)
	}
	c.DiskOpsV2 = true
	c.SentAt = now.Add(2 * time.Second)
	if err = s.RecordCheckin(req.Targets[0], c, now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err := s.ScriptRun(req, true, "safe", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.ScriptRun(req, true, "safe", diskAdmin())
	if err != nil || !replay.Replayed || replay.JobIDs[0] != result.JobIDs[0] {
		t.Fatal("replay", err)
	}
	job, err := s.Job(result.JobIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	desired, err := s.DesiredState(job.DesiredID)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := scriptcatalog.Decode([]byte(desired.Spec))
	if err != nil || len(spec.Policy) == 0 {
		t.Fatal("unpinned policy", err)
	}
	s.ConfigureDiskOpsV2Writes(false)
	if _, err = s.ClaimJob(job.JobID, req.Targets[0], now, time.Minute); err == nil {
		t.Fatal("claim bypassed flag")
	}
	s.ConfigureDiskOpsV2Writes(true)
	token, err := s.ClaimJob(job.JobID, req.Targets[0], now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdvanceJobByAgent(job.JobID, req.Targets[0], token, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	summary := DiskSafeEnvelope{}
	summary.Operation.Schema = "disk-safe/v2"
	summary.Operation.PolicyID = "disk-default"
	summary.Operation.PolicyDigest = "sha256:" + scriptcatalog.Digest(spec.Policy)
	summary.Summary.Schema = "fleet-disk-clean/v1"
	summary.Summary.Version = "2.0.0"
	summary.Summary.Scope = "user"
	summary.Summary.Host = "agent"
	summary.Summary.User = "agent"
	summary.Summary.Mode = "apply"
	summary.Summary.TS = now.Format(time.RFC3339)
	summary.Summary.ConfigDigest = summary.Operation.PolicyDigest
	summary.Summary.Disk.Mount = "/"
	raw := `{"mode":"apply","status":"skipped","note":"deferred: cache lock held by 2"}`
	summary.Summary.Categories = make(map[string]maintenance.SummaryCategory)
	var category maintenance.SummaryCategory
	_ = json.Unmarshal([]byte(raw), &category)
	summary.Summary.Categories["uv"] = category
	if err = s.RecordVerification(job.JobID, req.Targets[0], token, scriptcatalog.Kind, req.ScriptID, 0, string(mustScriptJSON(summary)), "", true, now); err != nil {
		t.Fatal(err)
	}
	status, err := s.DiskOpsStatus(req.Targets[0])
	if err != nil || status.LastSafeTier == nil || status.Skips["uv"] != "deferred: cache lock held by 2" {
		t.Fatalf("status %+v %v", status, err)
	}
}
func TestDiskSafeScheduleTemplateAndGating(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	var args map[string]string
	_ = json.Unmarshal(req.Args, &args)
	schedule, err := DiskScheduleTemplate("user", args["policy_id"], args["policy_digest"], req.Targets[0], 3, 17)
	if err != nil || schedule.Cron != "17 3 * * *" || schedule.CatchUp {
		t.Fatal("template", err)
	}
	schedule.Reason = "daily safe cleanup"
	p, err := s.ScheduleManage(schedule, "upsert", false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	schedule.PreviewDigest = p.PreviewDigest
	out, err := s.ScheduleManage(schedule, "upsert", true, "safe-schedule", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureDiskOpsV2Writes(false)
	if _, err = s.ScheduleRunNow(out.Schedule.ID, "run-disabled", diskAdmin()); err == nil {
		t.Fatal("scheduled job bypassed writes flag")
	}
	s.ConfigureDiskOpsV2Writes(true)
	jobs, err := s.ScheduleRunNow(out.Schedule.ID, "run-enabled", diskAdmin())
	if err != nil || len(jobs.JobIDs) != 1 {
		t.Fatal("run enabled", err)
	}
	job, _ := s.Job(jobs.JobIDs[0])
	desired, _ := s.DesiredState(job.DesiredID)
	spec, err := scriptcatalog.Decode([]byte(desired.Spec))
	if err != nil || len(spec.Policy) == 0 {
		t.Fatal("schedule policy not pinned")
	}
	_ = now
}

func TestDiskSafePolicyReplacementRejectsQueuedDispatch(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	p, err := s.ScriptRun(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = p.PreviewDigest
	out, err := s.ScriptRun(req, true, "queued", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	policy := DefaultDiskPolicy()
	policy.SafeTier.UserTmpMinDays = 15
	revision := int64(1)
	update := DiskPolicyRequest{ID: "disk-default", Body: mustScriptJSON(policy), ExpectedRevision: &revision, Reason: "retain older temporary files"}
	plan, err := s.DiskPolicyUpsert(update, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	update.ExpiresAt = plan.ExpiresAt
	update.PreviewDigest = plan.PreviewDigest
	if _, err = s.DiskPolicyUpsert(update, true, "replacement", diskAdmin()); err != nil {
		t.Fatal(err)
	}
	job, err := s.Job(out.JobIDs[0])
	if err != nil || job.State != deploy.Rejected {
		t.Fatal("queued policy job survived revocation", err)
	}
	if _, err = s.ClaimJob(job.JobID, req.Targets[0], now, time.Minute); err == nil {
		t.Fatal("revoked job claimed")
	}
}
