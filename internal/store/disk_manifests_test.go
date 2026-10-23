package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func manifestFixture(t *testing.T) (*Store, DiskActionRequest, time.Time) {
	t.Helper()
	s, req, now := deepFixture(t)
	job := deepJob(t, s, req, now)
	r := fixtureReport(req)
	r.Items[0].Identity = diskreport.Identity{Dev: 1, Inode: 42, Type: 0100000, Size: 2000, MtimeNS: now.UnixNano(), CtimeNS: now.UnixNano()}
	raw := mustScriptJSON(r)
	if _, err := s.DiskReportChunk(req.Targets[0], job, diskreport.Chunk{Digest: diskreport.Digest(raw), Data: raw}); err != nil {
		t.Fatal(err)
	}
	receipt, err := s.DiskReportComplete(req.Targets[0], job, diskreport.Complete{Digest: diskreport.Digest(raw), ItemCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	return s, DiskActionRequest{ReportID: receipt.ID, ReportDigest: receipt.Digest, Action: "quarantine", ItemIDs: []string{"candidate-1"}, Reason: "Reviewed old backup"}, now
}

func TestDiskManifestExactPrivateBindingAndProjection(t *testing.T) {
	s, req, _ := manifestFixture(t)
	out, err := s.DiskActionPreview(req, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	var body, digest string
	if err = s.rdb.QueryRow(`SELECT body,digest FROM ops_manifests WHERE id=?`, out.ManifestID).Scan(&body, &digest); err != nil {
		t.Fatal(err)
	}
	if diskreport.Digest([]byte(body)) != digest || digest != out.Approval.ItemDigest || out.Approval.Operation != "quarantine" || out.Approval.Actor != diskAdmin().AuthSubject {
		t.Fatal("binding mismatch")
	}
	var m DiskManifest
	if err = json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatal(err)
	}
	if m.Items[0].PrivatePath != "/home/private-account/private-project/archive.bak" || m.Items[0].Identity.Inode != 42 || m.TTLSeconds != 604800 || !m.Deadline.Equal(out.Approval.Deadline) {
		t.Fatal("exact identity lost")
	}
	public := string(mustScriptJSON(out))
	if strings.Contains(public, "private-account") || strings.Contains(public, "private-project") || strings.Contains(public, "private_path") {
		t.Fatal("private binding leaked")
	}
	if out.AllocatedBytes != 4096 || out.LogicalBytes != 2000 {
		t.Fatal("byte tally")
	}
	if _, err = s.db.Exec(`UPDATE ops_manifests SET body='{}' WHERE id=?`, out.ManifestID); err == nil {
		t.Fatal("manifest mutable")
	}
	// Separate actions always produce separate approval and manifest digests.
	req.Action = "delete"
	deleted, err := s.DiskActionPreview(req, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Digest == out.Digest || deleted.Approval.ID == out.Approval.ID || deleted.Approval.Operation != "delete" {
		t.Fatal("action approvals aliased")
	}
}

func TestDiskManifestRejectsUnreviewedSelectionAndToken(t *testing.T) {
	s, req, _ := manifestFixture(t)
	for _, mutate := range []func(*DiskActionRequest){
		func(r *DiskActionRequest) { r.ItemIDs = nil },
		func(r *DiskActionRequest) { r.ItemIDs = []string{"candidate-1", "candidate-1"} },
		func(r *DiskActionRequest) { r.ItemIDs = []string{"unseen"} },
		func(r *DiskActionRequest) { r.ItemIDs = make([]string, 101) },
		func(r *DiskActionRequest) { r.ReportDigest = "sha256:" + strings.Repeat("a", 64) },
		func(r *DiskActionRequest) { r.Action = "restore" },
		func(r *DiskActionRequest) { r.Reason = "" },
	} {
		bad := req
		mutate(&bad)
		if _, err := s.DiskActionPreview(bad, diskAdmin()); err == nil {
			t.Fatal("invalid selection accepted")
		}
	}
	token := diskAdmin()
	token.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err := s.DiskActionPreview(req, token); err == nil {
		t.Fatal("token admitted")
	}
	if _, err := s.db.Exec(`UPDATE disk_report_items SET body=json_set(body,'$.exclusion_reason','protected') WHERE report_id=?`, req.ReportID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiskActionPreview(req, diskAdmin()); err == nil {
		t.Fatal("protected item accepted")
	}
}

func TestDiskManifestFetchRequiresAssignedActiveJob(t *testing.T) {
	s, req, now := manifestFixture(t)
	out, err := s.DiskActionPreview(req, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	for _, machine := range []string{"wrong-machine", out.Approval.MachineID} {
		if _, err = s.DiskManifestForJob(machine, "no-job", out.ManifestID, out.Digest); err == nil {
			t.Fatal("unassigned fetch")
		}
	}
	// The trusted ledger's existing consumption tests exercise atomic job creation;
	// here construct an exact binding to test the independent retrieval boundary.
	var job string
	if err = s.rdb.QueryRow(`SELECT job_id FROM disk_reports WHERE id=?`, req.ReportID).Scan(&job); err != nil {
		t.Fatal(err)
	}
	var desired string
	if err = s.rdb.QueryRow(`SELECT desired_id FROM jobs WHERE job_id=?`, job).Scan(&desired); err != nil {
		t.Fatal(err)
	}
	args := mustScriptJSON(map[string]string{"manifest_id": out.ManifestID, "manifest_digest": out.Digest, "approval_id": out.Approval.ID})
	spec := mustScriptJSON(map[string]any{"kind": "script_v1", "script_id": "disk-approved-quarantine-v1", "script_sha256": strings.Repeat("a", 64), "execution_mode": "write", "args": json.RawMessage(args)})
	if _, err = s.db.Exec(`UPDATE desired_state SET spec=? WHERE desired_id=?`, string(spec), desired); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE ops_approvals SET state='approved',decision_actor=?,decided_at=? WHERE id=?`, diskAdmin().AuthSubject, fmtTime(now), out.Approval.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE ops_approvals SET state='consumed',job_id=?,consumed_at=? WHERE id=?`, job, fmtTime(now), out.Approval.ID); err != nil {
		t.Fatal(err)
	}
	// Until a reviewed catalog entry exists even an exact job must fail closed.
	if _, err = s.DiskManifestForJob(out.Approval.MachineID, job, out.ManifestID, out.Digest); err == nil {
		t.Fatal("unregistered action admitted")
	}
}

func TestDiskManifestDecisionDigestAndSingleConsumption(t *testing.T) {
	s, req, now := manifestFixture(t)
	out, err := s.DiskActionPreview(req, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureDiskOpsV2Writes(true)
	decision, err := s.OpsApprovalDecision(OpsApprovalDecisionRequest{ID: out.Approval.ID, Decision: "approved", Reason: req.Reason}, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	bad := decision.Request
	bad.ItemDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err = s.opsApprovalDecision(bad, true, "manifest-decision", diskAdmin(), nil); err == nil {
		t.Fatal("unbound digest approved")
	}
	// Exercise the trusted ledger primitive; public generic apply is separately
	// tested to reject manifest approvals requiring dedicated action confirmation.
	approved, err := s.opsApprovalDecision(decision.Request, true, "manifest-decision", diskAdmin(), nil)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	create := func(tx dbTx, a OpsApproval) (string, error) {
		calls++
		// A trusted factory fixture exercises the ledger, without enabling an action
		// entry or exposing an arbitrary factory to callers.
		d, r, err := createDesiredStateTx(tx, "machine", a.MachineID, "script_v1", "fixture", `{}`, "operator:human-admin", now)
		if err != nil {
			return "", err
		}
		return createManagedJobTx(tx, a.MachineID, d, r, NewJob{}, now)
	}
	badBinding := approved.Approval
	badBinding.ItemDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err = s.consumeOpsApproval(badBinding, "manifest-consume-bad", diskAdmin(), create); err == nil {
		t.Fatal("changed digest consumed")
	}
	consumed, err := s.consumeOpsApproval(approved.Approval, "manifest-consume", diskAdmin(), create)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := s.consumeOpsApproval(approved.Approval, "manifest-consume", diskAdmin(), create)
	if err != nil || replay.JobID != consumed.JobID || calls != 1 {
		t.Fatal("non-idempotent consumption", calls, err)
	}
	if _, err = s.consumeOpsApproval(approved.Approval, "manifest-consume-again", diskAdmin(), create); err == nil {
		t.Fatal("consumed twice")
	}
	token := diskAdmin()
	token.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err = s.consumeOpsApproval(approved.Approval, "manifest-consume", token, create); err == nil {
		t.Fatal("token replay")
	}
}

func TestDiskManifestStalePolicyAndAuditRollback(t *testing.T) {
	s, req, now := manifestFixture(t)
	s.nowFn = func() time.Time { return now.Add(6*time.Hour + time.Second) }
	if _, err := s.DiskActionPreview(req, diskAdmin()); err == nil {
		t.Fatal("stale report preview")
	}
	s.nowFn = func() time.Time { return now }
	if _, err := s.db.Exec(`CREATE TRIGGER fail_manifest_audit BEFORE INSERT ON audit_log WHEN NEW.action='ops-approval' AND NEW.outcome='ok' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiskActionPreview(req, diskAdmin()); err == nil {
		t.Fatal("unaudited preview committed")
	}
	for _, query := range []string{`SELECT COUNT(*) FROM ops_manifests`, `SELECT COUNT(*) FROM ops_approvals`} {
		var n int
		if err := s.rdb.QueryRow(query).Scan(&n); err != nil || n != 0 {
			t.Fatal("atomic preview residue", n, err)
		}
	}
	if _, err := s.db.Exec(`DROP TRIGGER fail_manifest_audit`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`UPDATE ops_policies SET superseded_at=?`, fmtTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiskActionPreview(req, diskAdmin()); err == nil {
		t.Fatal("revoked policy preview")
	}
}
