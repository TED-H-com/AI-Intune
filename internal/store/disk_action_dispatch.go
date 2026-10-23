package store

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// ConfigureDiskManifestSigningKey is process configuration, never an operator
// API. The default has no signing authority and cannot dispatch action jobs.
func (s *Store) ConfigureDiskManifestSigningKey(raw []byte) error {
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || len(raw) > 32768 {
		return operatorError("PRECONDITION_FAILED", "invalid manifest signing key")
	}
	var key *rsa.PrivateKey
	var err error
	if block.Type == "RSA PRIVATE KEY" {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	} else if block.Type == "PRIVATE KEY" {
		var parsed any
		parsed, err = x509.ParsePKCS8PrivateKey(block.Bytes)
		key, _ = parsed.(*rsa.PrivateKey)
	}
	if err != nil || key == nil || key.N.BitLen() < 2048 || key.N.BitLen() > 4096 || key.E != 65537 || key.Validate() != nil {
		return operatorError("PRECONDITION_FAILED", "unsupported manifest signing key")
	}
	s.diskManifestSigner.Store(key)
	return nil
}

// DiskActionDecide consumes the approval with job creation in the canonical
// human decision transaction. No approved-without-job intermediate is exposed.
func (s *Store) DiskActionDecide(req OpsApprovalDecisionRequest, apply bool, key string, audit AuditEntry) (OpsApprovalDecisionResult, error) {
	if strings.TrimSpace(req.Reason) != "" {
		normalizedReason, reasonErr := boundedtext.Reason(req.Reason)
		if reasonErr != nil {
			return OpsApprovalDecisionResult{}, operatorError(OperatorCodeReasonRequired, reasonErr.Error())
		}
		req.Reason = normalizedReason
	}

	if err := humanDiskAdmin(audit); err != nil {
		return OpsApprovalDecisionResult{}, err
	}
	if apply && req.Decision == "approved" && s.diskManifestSigner.Load() == nil {
		return OpsApprovalDecisionResult{}, operatorError("PRECONDITION_FAILED", "manifest signing key not configured")
	}
	return s.opsApprovalDecision(req, apply, key, audit, func(tx dbTx, a OpsApproval) (string, error) {
		return s.createDiskActionJobTx(tx, a)
	})
}

func (s *Store) createDiskActionJobTx(tx dbTx, a OpsApproval) (string, error) {
	var id, digest, body string
	if err := tx.QueryRow(`SELECT id,digest,body FROM ops_manifests WHERE approval_id=? AND machine_id=?`, a.ID, a.MachineID).Scan(&id, &digest, &body); err != nil {
		return "", err
	}
	var manifest DiskManifest
	if json.Unmarshal([]byte(body), &manifest) != nil || digest != a.ItemDigest || "sha256:"+scriptcatalog.Digest([]byte(body)) != digest || manifest.Initiator != a.Actor || manifest.Action != a.Operation || manifest.PolicyRevision != a.PolicyRevision || manifest.PolicyDigest != a.PolicyDigest || manifest.ApprovalID != a.ID || !manifest.Deadline.Equal(a.Deadline) {
		return "", operatorError("PRECONDITION_FAILED", "action manifest binding mismatch")
	}
	if manifest.Action == "restore" {
		for _, item := range manifest.Items {
			var identity, parent string
			if err := tx.QueryRow(`SELECT identity,original_parent FROM disk_quarantine WHERE manifest_id=? AND item_id=? AND state IN ('quarantined','restore_pending')`, manifest.QuarantineManifestID, item.ID).Scan(&identity, &parent); err != nil {
				return "", operatorError("PRECONDITION_FAILED", "restore item no longer retained")
			}
			if identity != string(mustScriptJSON(item.Identity)) || parent != string(mustScriptJSON(item.OriginalParent)) {
				return "", operatorError("REVISION_CONFLICT", "restore identity changed since preview")
			}
		}
	}
	e, ok := scriptcatalog.Lookup(scriptcatalog.DiskActionScript(a.Operation))
	if !ok || !scriptcatalog.IsDiskAction(e.ID) || e.Mode != "write" || scriptcatalog.Digest(e.Bytes) != e.SHA256 {
		return "", operatorError("PRECONDITION_FAILED", "unreviewed action script")
	}
	var rawPolicy string
	if err := tx.QueryRow(`SELECT body FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, a.PolicyID, a.PolicyRevision, a.PolicyDigest).Scan(&rawPolicy); err != nil {
		return "", err
	}
	_, policy, actual, err := CanonicalDiskPolicy(json.RawMessage(rawPolicy))
	if err != nil || actual != a.PolicyDigest {
		return "", operatorError("PRECONDITION_FAILED", "policy integrity mismatch")
	}
	args := mustScriptJSON(map[string]string{"manifest_id": id, "manifest_digest": digest, "approval_id": a.ID})
	req := ScriptRunRequest{ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: args, Targets: []string{a.MachineID}, Reason: a.DecisionReason, TimeoutSeconds: e.DefaultTimeout}
	if err = s.diskSafeGateTx(tx, req, e, true); err != nil {
		return "", err
	}
	if err = validateScriptTargetsTx(tx, req, e); err != nil {
		return "", err
	}
	spec := mustScriptJSON(scriptcatalog.Spec{Kind: scriptcatalog.Kind, ExecutionMode: e.Mode, ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: args, Policy: policy})
	now := s.now().UTC()
	desired, rev, err := createDesiredStateTx(tx, "machine", a.MachineID, scriptcatalog.Kind, e.ID, string(spec), "operator:"+a.DecisionActor, now)
	if err != nil {
		return "", err
	}
	if a.Operation == "quarantine" {
		if err = ensureExpiryScheduleTx(tx, a, now); err != nil {
			return "", err
		}
	}
	return createManagedJobTx(tx, a.MachineID, desired, rev, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(spec), ExecutionTimeout: e.DefaultTimeout, Irreversible: a.Operation == "delete"}, now)
}

// SignedDiskManifestForJob also supplies the current policy and a short-lived
// grant. The helper renews it before each mutation, so policy/config revocation
// and Hub outages stop work at the next safe item boundary.
func (s *Store) SignedDiskManifestForJob(machine, job, id, digest string) (scriptcatalog.SignedDiskGrant, error) {
	var out scriptcatalog.SignedDiskGrant
	if id == "expiry" {
		return s.signedExpiryGrant(machine, job, digest)
	}
	key := s.diskManifestSigner.Load()
	if !s.DiskOpsWritesEnabled() || key == nil {
		return out, operatorError("PRECONDITION_FAILED", "disk action authority unavailable")
	}
	tx, err := s.beginWrite(context.Background(), "signed_disk_manifest")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var argsRaw string
	if err = tx.QueryRow(`SELECT d.spec FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.job_id=? AND j.machine_id=?`, job, machine).Scan(&argsRaw); err != nil {
		return out, operatorError("FORBIDDEN", "job not assigned")
	}
	spec, e := scriptcatalog.Decode([]byte(argsRaw))
	entry, ok := scriptcatalog.Lookup(spec.ScriptID)
	if e != nil || !ok {
		return out, operatorError("PRECONDITION_FAILED", "invalid job")
	}
	if err = s.diskSafeGateTx(tx, ScriptRunRequest{Args: spec.Args, Targets: []string{machine}}, entry, true); err != nil {
		return out, err
	}
	now := s.now().UTC()
	raw, deadline, err := diskManifestForJobTx(tx, machine, job, id, digest, now)
	if err != nil {
		return out, err
	}
	var m DiskManifest
	if err = json.Unmarshal(raw, &m); err != nil {
		return out, err
	}
	var rawPolicy string
	if err = tx.QueryRow(`SELECT body FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, m.PolicyID, m.PolicyRevision, m.PolicyDigest).Scan(&rawPolicy); err != nil {
		return out, operatorError("PRECONDITION_FAILED", "policy revoked")
	}
	_, policy, actual, err := CanonicalDiskPolicy(json.RawMessage(rawPolicy))
	if err != nil || actual != m.PolicyDigest {
		return out, operatorError("PRECONDITION_FAILED", "policy integrity mismatch")
	}
	args := mustScriptJSON(map[string]string{"manifest_id": m.ID, "manifest_digest": digest, "approval_id": m.ApprovalID})
	expires := now.Add(15 * time.Second)
	if deadline.Before(expires) {
		expires = deadline
	}
	entry, _ = scriptcatalog.Lookup(scriptcatalog.DiskActionScript(m.Action))
	grant := scriptcatalog.DiskGrant{ScriptSHA256: entry.SHA256, Schema: "disk-grant/v1", Action: m.Action, ScriptID: scriptcatalog.DiskActionScript(m.Action), MachineID: machine, JobID: job, ArgsDigest: "sha256:" + scriptcatalog.Digest(args), PolicyID: m.PolicyID, PolicyDigest: m.PolicyDigest, Policy: policy, Manifests: [][]byte{raw}, ExpiresAt: expires}
	signed, err := scriptcatalog.SignDiskGrant(key, grant)
	if err != nil {
		return out, err
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	return signed, nil
}

func (s *Store) DiskRestoreApply(req OpsApprovalDecisionRequest, apply bool, key string, audit AuditEntry) (OpsApprovalDecisionResult, error) {
	if strings.TrimSpace(req.Reason) != "" {
		normalizedReason, reasonErr := boundedtext.Reason(req.Reason)
		if reasonErr != nil {
			return OpsApprovalDecisionResult{}, operatorError(OperatorCodeReasonRequired, reasonErr.Error())
		}
		req.Reason = normalizedReason
	}

	if err := humanDiskAdmin(audit); err != nil {
		return OpsApprovalDecisionResult{}, err
	}
	a, err := s.OpsApproval(req.ID, s.now().UTC())
	if err != nil {
		return OpsApprovalDecisionResult{}, err
	}
	if a.Operation != "restore" || req.Decision != "approved" || req.PreviewDigest == "" {
		return OpsApprovalDecisionResult{}, operatorError("BAD_REQUEST", "exact restore approval preview required")
	}
	return s.DiskActionDecide(req, apply, key, audit)
}
