package store

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"testing"
	"time"
)

func quarantineFixture(t *testing.T) (*Store, DiskActionPreview, string, DiskActionResults, time.Time) {
	t.Helper()
	s, p, _, now := dispatchFixture(t)
	decision := dispatchDecision(t, s, p)
	applied, err := s.DiskActionDecide(decision, true, "q-decision", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	job := applied.Approval.JobID
	lease, err := s.ClaimJob(job, p.Approval.MachineID, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdvanceJobByAgent(job, p.Approval.MachineID, lease, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	var body string
	if err = s.rdb.QueryRow(`SELECT body FROM ops_manifests WHERE id=?`, p.ManifestID).Scan(&body); err != nil {
		t.Fatal(err)
	}
	var m DiskManifest
	_ = json.Unmarshal([]byte(body), &m)
	i := m.Items[0]
	post := i.Identity
	post.CtimeNS += 1000
	r := DiskActionResults{Schema: "disk-action-result/v1", JobID: job, Items: []DiskActionItemResult{{ManifestID: m.ID, ItemID: i.ID, Status: "quarantined", Record: &DiskActionRecord{State: "quarantined", Identity: post, OriginalParent: []uint64{1, 99}, OwnerUID: i.OwnerUID, QuarantinedAt: float64(now.Unix()), ExpiresAt: float64(now.Add(QuarantineTTL).Unix())}}}}
	return s, p, job, r, now
}
func TestQuarantineReceiptBindingRestoreAndMetrics(t *testing.T) {
	s, p, job, req, now := quarantineFixture(t)
	if _, err := s.DiskActionResults("wrong", job, req); err == nil {
		t.Fatal("wrong machine accepted")
	}
	bad := req
	bad.Items = append([]DiskActionItemResult(nil), req.Items...)
	bad.Items[0].ItemID = "unapproved"
	if _, err := s.DiskActionResults(p.Approval.MachineID, job, bad); err == nil {
		t.Fatal("unapproved result accepted")
	}
	digest, err := s.DiskActionResults(p.Approval.MachineID, job, req)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.DiskActionResults(p.Approval.MachineID, job, req)
	if err != nil || replay != digest {
		t.Fatal("receipt replay", err)
	}
	list, err := s.DiskQuarantineList(p.Approval.MachineID)
	if err != nil || len(list) != 1 || list[0].DisplayPath != "~/…/archive.bak" {
		t.Fatal("quarantine projection", list, err)
	}
	metrics, err := s.DiskActionMetrics(p.Approval.MachineID, now)
	if err != nil || metrics.QuarantinedBytes != 4096 || metrics.FreedBytes != 0 || metrics.Samples != 1 {
		t.Fatal("metrics", metrics, err)
	}
	restore, err := s.DiskRestorePreview(DiskRestoreRequest{QuarantineID: p.ManifestID, ItemIDs: []string{"candidate-1"}, Reason: "Restore reviewed backup"}, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	var body string
	_ = s.rdb.QueryRow(`SELECT body FROM ops_manifests WHERE id=?`, restore.ManifestID).Scan(&body)
	var m DiskManifest
	_ = json.Unmarshal([]byte(body), &m)
	if m.Action != "restore" || m.QuarantineManifestID != p.ManifestID || m.Items[0].Identity.CtimeNS != req.Items[0].Record.Identity.CtimeNS || len(m.Items[0].OriginalParent) != 2 {
		t.Fatal("restore snapshot")
	}
	if _, err = s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(now), job); err != nil {
		t.Fatal(err)
	}
	plan, err := s.DiskActionDecide(OpsApprovalDecisionRequest{ID: restore.Approval.ID, Decision: "approved", Reason: "Restore reviewed backup"}, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.DiskRestoreApply(plan.Request, true, "restore", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	rr := req
	rr.JobID = applied.Approval.JobID
	rr.Items = append([]DiskActionItemResult(nil), req.Items...)
	rr.Items[0].ManifestID = restore.ManifestID
	rr.Items[0].Status = "restored"
	record := *req.Items[0].Record
	record.State = "restored"
	rr.Items[0].Record = &record
	if _, err = s.DiskActionResults(p.Approval.MachineID, rr.JobID, rr); err != nil {
		t.Fatal(err)
	}
	metrics, err = s.DiskActionMetrics(p.Approval.MachineID, now)
	if err != nil || metrics.QuarantinedBytes != 0 || metrics.RestoreSuccess != 1 || metrics.FreedBytes != 0 {
		t.Fatal("restore metrics", metrics, err)
	}
	if _, err = s.DiskActionResults(p.Approval.MachineID, job, req); err != nil {
		t.Fatal("old exact receipt retry", err)
	}
	list, _ = s.DiskQuarantineList(p.Approval.MachineID)
	if len(list) != 0 {
		t.Fatal("terminal item resurrected")
	}
}
func TestApprovedExpiryScheduleAndRevokedPolicy(t *testing.T) {
	s, p, job, req, now := quarantineFixture(t)
	if _, err := s.DiskActionResults(p.Approval.MachineID, job, req); err != nil {
		t.Fatal(err)
	}
	var schedule, cron string
	if err := s.rdb.QueryRow(`SELECT id,cron FROM schedules WHERE script_id='disk-quarantine-expire-v1'`).Scan(&schedule, &cron); err != nil || cron != "10 6 * * *" {
		t.Fatal("daily expiry schedule", cron, err)
	}
	due := now.Add(QuarantineTTL + time.Minute)
	s.nowFn = func() time.Time { return due }
	tx, err := s.beginWrite(t.Context(), "expiry-test")
	if err != nil {
		t.Fatal(err)
	}
	selection, _, err := expirySelectionTx(tx, p.Approval.MachineID, p.Approval.PolicyID, p.Approval.PolicyDigest, due)
	if err != nil || len(selection[p.ManifestID]) != 1 {
		t.Fatal("approved selection", selection, err)
	}
	tx.Rollback()
	if _, err = s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(now), job); err != nil {
		t.Fatal(err)
	}
	plan, err := s.DiskScheduleRunNow(schedule, "", "", false, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	result, err := s.DiskScheduleRunNow(schedule, plan.PreviewDigest, "expire-now", true, diskAdmin())
	if err != nil || len(result.JobIDs) != 1 {
		t.Fatal("expiry dispatch", result, err)
	}
	ej := result.JobIDs[0]
	lease, err := s.ClaimJob(ej, p.Approval.MachineID, due, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdvanceJobByAgent(ej, p.Approval.MachineID, lease, deploy.Start, due); err != nil {
		t.Fatal(err)
	}
	signed, err := s.SignedDiskManifestForJob(p.Approval.MachineID, ej, "expiry", p.Approval.PolicyDigest)
	if err != nil {
		t.Fatal(err)
	}
	var grant scriptcatalog.DiskGrant
	if json.Unmarshal(signed.Payload, &grant) != nil || len(grant.Selection[p.ManifestID]) != 1 || grant.Action != "expire" {
		t.Fatal("expiry grant")
	}
	if _, err = s.db.Exec(`UPDATE ops_policies SET superseded_at=?`, fmtTime(due)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SignedDiskManifestForJob(p.Approval.MachineID, ej, "expiry", p.Approval.PolicyDigest); err == nil {
		t.Fatal("revoked expiry grant")
	}
}
func TestActionReadinessAndStaleRestoreAdmission(t *testing.T) {
	s, p, _, _ := dispatchFixture(t)
	plan := dispatchDecision(t, s, p)
	if _, err := s.db.Exec(`DELETE FROM machine_job_capabilities WHERE capability LIKE 'disk_actions_v1:%'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiskActionDecide(plan, true, "no-helper", diskAdmin()); err == nil {
		t.Fatal("missing helper admitted")
	}
}

func TestManifestApprovalCannotUseGenericApply(t *testing.T) {
	s, p, _, _ := dispatchFixture(t)
	plan, err := s.OpsApprovalDecision(OpsApprovalDecisionRequest{ID: p.Approval.ID, Decision: "approved", Reason: "review exact items"}, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.OpsApprovalDecision(plan.Request, true, "generic", diskAdmin()); err == nil {
		t.Fatal("generic manifest approval applied without dedicated confirmation")
	}
	a, err := s.OpsApproval(p.Approval.ID, s.now().UTC())
	if err != nil || a.State != "pending" || a.JobID != "" {
		t.Fatal(a, err)
	}
}

func TestRestoreNeedsRecoveryLedgerAndAdmission(t *testing.T) {
	s, p, job, receipt, now := quarantineFixture(t)
	if _, err := s.DiskActionResults(p.Approval.MachineID, job, receipt); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=? WHERE job_id=?`, fmtTime(now), job); err != nil {
		t.Fatal(err)
	}
	preview, err := s.DiskRestorePreview(DiskRestoreRequest{QuarantineID: p.ManifestID, ItemIDs: []string{"candidate-1"}, Reason: "Restore reviewed item"}, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	plan, err := s.DiskActionDecide(OpsApprovalDecisionRequest{ID: preview.Approval.ID, Decision: "approved", Reason: "Restore reviewed item"}, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	applied, err := s.DiskRestoreApply(plan.Request, true, "needs-recovery", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	observation := receipt
	observation.JobID = applied.Approval.JobID
	observation.Items = append([]DiskActionItemResult(nil), receipt.Items...)
	observation.Items[0].ManifestID = preview.ManifestID
	observation.Items[0].Status = "skipped"
	observation.Items[0].Reason = "needs_recovery"
	record := *receipt.Items[0].Record
	record.State = "needs_recovery"
	observation.Items[0].Record = &record
	if _, err = s.DiskActionResults(p.Approval.MachineID, observation.JobID, observation); err != nil {
		t.Fatal(err)
	}
	list, err := s.DiskQuarantineList(p.Approval.MachineID)
	if err != nil || len(list) != 1 || list[0].State != "needs_recovery" {
		t.Fatal(list, err)
	}
	if _, err = s.DiskRestorePreview(DiskRestoreRequest{QuarantineID: p.ManifestID, ItemIDs: []string{"candidate-1"}, Reason: "Attempt automatic recovery"}, diskAdmin()); err == nil {
		t.Fatal("recovery conflict admitted ordinary restore")
	}
	metrics, err := s.DiskActionMetrics(p.Approval.MachineID, now)
	if err != nil || metrics.FreedBytes != 0 || metrics.RestoreSuccess != 0 || metrics.RestoreConflicts != 1 || metrics.QuarantinedBytes != 4096 {
		t.Fatal(metrics, err)
	}
}
