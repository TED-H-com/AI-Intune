package store

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

func dispatchFixture(t *testing.T) (*Store, DiskActionPreview, *rsa.PrivateKey, time.Time) {
	t.Helper()
	s, req, now := manifestFixture(t)
	if _, err := s.db.Exec(`UPDATE jobs SET state='succeeded',terminal_at=?`, fmtTime(now)); err != nil {
		t.Fatal(err)
	}
	out, err := s.DiskActionPreview(req, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	raw := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err = s.ConfigureDiskManifestSigningKey(raw); err != nil {
		t.Fatal(err)
	}
	s.ConfigureDiskOpsV2Writes(true)
	if _, err = s.db.Exec(`INSERT OR IGNORE INTO machine_job_capabilities SELECT machine_id,sent_at,?,1 FROM machine_checkins WHERE machine_id=? ORDER BY received_at DESC,rowid DESC LIMIT 1`, "disk_actions_v1:"+scriptcatalog.Digest(x509.MarshalPKCS1PublicKey(&key.PublicKey)), out.Approval.MachineID); err != nil {
		t.Fatal(err)
	}
	return s, out, key, now
}
func dispatchDecision(t *testing.T, s *Store, out DiskActionPreview) OpsApprovalDecisionRequest {
	t.Helper()
	plan, err := s.DiskActionDecide(OpsApprovalDecisionRequest{ID: out.Approval.ID, Decision: "approved", Reason: "Review exact selected backup"}, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	return plan.Request
}
func TestDiskActionAtomicJobApprovalBindingsReplayAndSignature(t *testing.T) {
	s, out, key, now := dispatchFixture(t)
	req := dispatchDecision(t, s, out)
	bad := req
	bad.ItemDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := s.DiskActionDecide(bad, true, "action-decide", diskAdmin()); err == nil {
		t.Fatal("digest not bound")
	}
	result, err := s.DiskActionDecide(req, true, "action-decide", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if result.Approval.State != "consumed" || result.Approval.JobID == "" {
		t.Fatal("approval and job not atomic")
	}
	replay, err := s.DiskActionDecide(req, true, "action-decide", diskAdmin())
	if err != nil || !replay.Replayed || replay.Approval.JobID != result.Approval.JobID {
		t.Fatal("replay changed job", err)
	}
	if _, err = s.DiskActionDecide(req, true, "second-consume", diskAdmin()); err == nil {
		t.Fatal("second consume")
	}
	token := diskAdmin()
	token.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err = s.DiskActionDecide(req, true, "action-decide", token); err == nil {
		t.Fatal("token replay")
	}
	if _, err = s.OpsApprovalDecision(req, true, "action-decide", diskAdmin()); err == nil {
		t.Fatal("dedicated receipt replayed through generic decision")
	}
	job := result.Approval.JobID
	machine := out.Approval.MachineID
	if _, err = s.SignedDiskManifestForJob(machine, job, out.ManifestID, out.Digest); err == nil {
		t.Fatal("not-started fetch")
	}
	lease, err := s.ClaimJob(job, machine, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.AdvanceJobByAgent(job, machine, lease, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	signed, err := s.SignedDiskManifestForJob(machine, job, out.ManifestID, out.Digest)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(signed.Payload)
	if err = rsa.VerifyPKCS1v15(&key.PublicKey, crypto.SHA256, digest[:], signed.Signature); err != nil {
		t.Fatal(err)
	}
	var grant scriptcatalog.DiskGrant
	if err = json.Unmarshal(signed.Payload, &grant); err != nil {
		t.Fatal(err)
	}
	if grant.JobID != job || grant.MachineID != machine || grant.Action != "quarantine" || grant.ExpiresAt.Sub(now) != 15*time.Second || len(grant.Manifests) != 1 {
		t.Fatal("signed grant binding")
	}
	if "sha256:"+scriptcatalog.Digest(grant.Manifests[0]) != out.Digest || "sha256:"+scriptcatalog.Digest(grant.Policy) != out.Approval.PolicyDigest {
		t.Fatal("private bytes not digest bound")
	}
	if _, err = s.db.Exec(`UPDATE jobs SET lease_expires_at=? WHERE job_id=?`, fmtTime(now.Add(5*time.Second)), job); err != nil {
		t.Fatal(err)
	}
	short, err := s.SignedDiskManifestForJob(machine, job, out.ManifestID, out.Digest)
	if err != nil {
		t.Fatal(err)
	}
	var shortGrant scriptcatalog.DiskGrant
	if err = json.Unmarshal(short.Payload, &shortGrant); err != nil || !shortGrant.ExpiresAt.Equal(now.Add(5*time.Second)) {
		t.Fatal("grant outlives job lease", err)
	}
	s.ConfigureDiskOpsV2Writes(false)
	if _, err = s.SignedDiskManifestForJob(machine, job, out.ManifestID, out.Digest); err == nil {
		t.Fatal("disabled dispatch renewed")
	}
	s.ConfigureDiskOpsV2Writes(true)
	for _, binding := range [][4]string{{"wrong", job, out.ManifestID, out.Digest}, {machine, "no-job", out.ManifestID, out.Digest}, {machine, job, out.ManifestID, "sha256:" + strings.Repeat("b", 64)}} {
		if _, err = s.SignedDiskManifestForJob(binding[0], binding[1], binding[2], binding[3]); err == nil {
			t.Fatal("wrong grant binding")
		}
	}
	s.nowFn = func() time.Time { return now.Add(31 * time.Minute) }
	if _, err = s.SignedDiskManifestForJob(machine, job, out.ManifestID, out.Digest); err == nil {
		t.Fatal("expired manifest fetch")
	}
	s.nowFn = func() time.Time { return now }
	if _, err = s.db.Exec(`UPDATE ops_policies SET superseded_at=?`, fmtTime(now)); err != nil {
		t.Fatal(err)
	}
	if _, err = s.SignedDiskManifestForJob(machine, job, out.ManifestID, out.Digest); err == nil {
		t.Fatal("revoked policy grant")
	}
}
func TestDiskActionDispatchFailureRollsBackHumanDecision(t *testing.T) {
	s, out, _, _ := dispatchFixture(t)
	req := dispatchDecision(t, s, out)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_action_audit BEFORE INSERT ON audit_log WHEN NEW.action='ops-approval' AND NEW.outcome='ok' BEGIN SELECT RAISE(ABORT,'injected failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DiskActionDecide(req, true, "action-rollback", diskAdmin()); err == nil {
		t.Fatal("unaudited job created")
	}
	var state string
	var count int
	if err := s.rdb.QueryRow(`SELECT state FROM ops_approvals WHERE id=?`, out.Approval.ID).Scan(&state); err != nil || state != "pending" {
		t.Fatal("decision not rolled back", state, err)
	}
	if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 1 {
		t.Fatal("job residue", count, err)
	}
}
func TestDiskActionsCannotUseGenericScriptOrScheduleAuthorization(t *testing.T) {
	s, out, _, _ := dispatchFixture(t)
	for _, id := range []string{"disk-approved-quarantine-v1", "disk-approved-delete-v1", "disk-quarantine-restore-v1", "disk-quarantine-expire-v1"} {
		entry, _ := scriptcatalog.Lookup(id)
		args := mustScriptJSON(map[string]string{"manifest_id": out.ManifestID, "manifest_digest": out.Digest, "approval_id": out.Approval.ID})
		if id == "disk-quarantine-expire-v1" {
			args = mustScriptJSON(map[string]string{"policy_id": out.Approval.PolicyID, "policy_digest": out.Approval.PolicyDigest})
		}
		req := ScriptRunRequest{ScriptID: id, ScriptSHA256: entry.SHA256, Args: args, Targets: []string{out.Approval.MachineID}, Reason: "generic bypass attempt"}
		if _, err := s.ScriptRun(req, false, "", diskAdmin()); err == nil {
			t.Fatal("generic action admitted", id)
		}
		token := diskAdmin()
		token.AuthMethod = operatorauth.AuthMethodServiceToken
		token.AuthCapability = "operate"
		if _, err := s.ScriptRun(req, false, "", token); err == nil {
			t.Fatal("token eligible", id)
		}
		if err := scheduleScope(entry, diskAdmin()); err == nil && id != "disk-quarantine-expire-v1" {
			t.Fatal("generic action schedule admitted", id)
		}
	}
}
