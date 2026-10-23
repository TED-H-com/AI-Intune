package store

import (
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"time"
)

// diskSafePolicyTx resolves only the current immutable policy revision.
func diskSafePolicyTx(tx dbTx, req ScriptRunRequest, entry scriptcatalog.Entry) (json.RawMessage, error) {
	if !scriptcatalog.IsDisk(entry.ID) {
		return nil, nil
	}
	var args struct {
		Scope  string `json:"scope"`
		ID     string `json:"policy_id"`
		Digest string `json:"policy_digest"`
	}
	if json.Unmarshal(req.Args, &args) != nil {
		return nil, operatorError("BAD_REQUEST", "invalid disk args")
	}
	if scriptcatalog.IsDiskAction(entry.ID) && entry.ID != "disk-quarantine-expire-v1" {
		var binding struct {
			ID       string `json:"manifest_id"`
			Digest   string `json:"manifest_digest"`
			Approval string `json:"approval_id"`
		}
		if json.Unmarshal(req.Args, &binding) != nil {
			return nil, operatorError("BAD_REQUEST", "invalid action binding")
		}
		var body string
		if err := tx.QueryRow(`SELECT body FROM ops_manifests WHERE id=? AND digest=? AND approval_id=?`, binding.ID, binding.Digest, binding.Approval).Scan(&body); err != nil {
			return nil, operatorError("PRECONDITION_FAILED", "action manifest not bound")
		}
		var manifest DiskManifest
		if json.Unmarshal([]byte(body), &manifest) != nil {
			return nil, operatorError("PRECONDITION_FAILED", "invalid action manifest")
		}
		args.ID = manifest.PolicyID
		args.Digest = manifest.PolicyDigest
	}
	var raw, digest string
	err := tx.QueryRow(`SELECT body,digest FROM ops_policies WHERE id=? AND superseded_at IS NULL ORDER BY revision DESC LIMIT 1`, args.ID).Scan(&raw, &digest)
	if err == sql.ErrNoRows {
		return nil, operatorError("PRECONDITION_FAILED", "disk policy missing or revoked")
	}
	if err != nil {
		return nil, err
	}
	if digest != args.Digest {
		return nil, operatorError("REVISION_CONFLICT", "disk policy digest changed")
	}
	_, canonical, actual, err := CanonicalDiskPolicy(json.RawMessage(raw))
	if err != nil || actual != digest {
		return nil, operatorError("PRECONDITION_FAILED", "disk policy integrity mismatch")
	}
	return canonical, nil
}
func (s *Store) diskSafeGateTx(tx dbTx, req ScriptRunRequest, entry scriptcatalog.Entry, admission ...bool) error {
	return s.diskSafeGateTxAt(tx, req, entry, s.now().UTC(), admission...)
}
func (s *Store) diskSafeGateTxAt(tx dbTx, req ScriptRunRequest, entry scriptcatalog.Entry, now time.Time, admission ...bool) error {
	if !scriptcatalog.IsDisk(entry.ID) {
		return nil
	}
	if entry.Mode == "write" && (len(admission) == 0 || admission[0]) && !s.DiskOpsWritesEnabled() {
		return operatorError("PRECONDITION_FAILED", "disk_ops_v2_writes is disabled")
	}
	if _, err := diskSafePolicyTx(tx, req, entry); err != nil {
		return err
	}
	if scriptcatalog.IsDiskAction(entry.ID) {
		signer := s.diskManifestSigner.Load()
		if signer == nil {
			return operatorError("PRECONDITION_FAILED", "disk manifest signing key unavailable")
		}
		capability := "disk_actions_v1:" + scriptcatalog.Digest(x509.MarshalPKCS1PublicKey(&signer.PublicKey))
		for _, machine := range req.Targets {
			var ready int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM machine_checkins c JOIN machine_job_capabilities cap ON cap.machine_id=c.machine_id AND cap.sent_at=c.sent_at WHERE c.rowid=(SELECT rowid FROM machine_checkins WHERE machine_id=? ORDER BY received_at DESC,rowid DESC LIMIT 1) AND cap.capability=? AND cap.supported=1`, machine, capability).Scan(&ready); err != nil {
				return err
			}
			if ready != 1 {
				return operatorError("PRECONDITION_FAILED", "target lacks the current disk action helper and pinned signing key")
			}
		}
	}
	for _, id := range req.Targets {
		if entry.ID == "disk-safe-clean-v2" && (len(admission) == 0 || admission[0]) {
			var args struct {
				Scope string `json:"scope"`
			}
			_ = json.Unmarshal(req.Args, &args)
			var state string
			e := tx.QueryRow(`SELECT state FROM disk_ownership WHERE machine_id=? AND scope=?`, id, args.Scope).Scan(&state)
			if e == sql.ErrNoRows || (e == nil && state != "hub-owned") {
				return operatorError("PRECONDITION_FAILED", "disk scope is not hub-owned")
			}
			if e != nil {
				return e
			}
			var raw, received string
			e = tx.QueryRow(`SELECT body,received_at FROM disk_timer_observations WHERE machine_id=? AND scope=? ORDER BY receipt_seq DESC LIMIT 1`, id, args.Scope).Scan(&raw, &received)
			if e == sql.ErrNoRows {
				return operatorError("PRECONDITION_FAILED", "fresh known disabled local timer evidence required")
			}
			if e != nil {
				return e
			}
			var o struct {
				Scope         string `json:"scope"`
				Known         *bool  `json:"known"`
				Enabled       *bool  `json:"enabled"`
				Active        *bool  `json:"active"`
				ServiceActive *bool  `json:"service_active"`
			}
			var observation model.DiskTimerObservation
			malformed := len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &observation) != nil || observation.ObservedAt.IsZero()
			at, e := time.Parse(time.RFC3339Nano, received)
			if malformed || e != nil || at.After(now) || now.Sub(at) > 15*time.Minute || len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &o) != nil || o.Scope != args.Scope || o.Known == nil || !*o.Known || o.Enabled == nil || o.Active == nil || o.ServiceActive == nil {
				return operatorError("PRECONDITION_FAILED", "fresh known disabled local timer evidence required")
			}
			if *o.Enabled || *o.Active || *o.ServiceActive {
				return operatorError("PRECONDITION_FAILED", "dual ownership: local timer or service is active")
			}

		}
		if entry.ID == "disk-deep-report-v1" && (len(admission) > 0 && admission[0]) {
			available, err := deepAvailableTx(tx, id, s.now().UTC())
			if err != nil {
				return err
			}
			if !available {
				return operatorError("PRECONDITION_FAILED", "deep report coalesced within six hours")
			}
		}

		var supported sql.NullBool
		err := tx.QueryRow(`SELECT cap.supported FROM machine_checkins c LEFT JOIN machine_job_capabilities cap ON cap.machine_id=c.machine_id AND cap.sent_at=c.sent_at AND cap.capability='disk_ops_v2' WHERE c.machine_id=? ORDER BY c.received_at DESC,c.rowid DESC LIMIT 1`, id).Scan(&supported)
		if err == sql.ErrNoRows || (err == nil && (!supported.Valid || !supported.Bool)) {
			return operatorError("PRECONDITION_FAILED", "target does not advertise disk_ops_v2")
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// DiskScheduleTemplate is generic UTC standing authorization; offsets are explicit.
func DiskScheduleTemplate(scope, policyID, digest, machine string, hour, minute int) (ScheduleRequest, error) {
	if (scope != "user" && scope != "root") || hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return ScheduleRequest{}, operatorError("BAD_REQUEST", "invalid scope or UTC offset")
	}
	entry, _ := scriptcatalog.Lookup("disk-safe-clean-v2")
	args := mustScriptJSON(map[string]string{"scope": scope, "policy_id": policyID, "policy_digest": digest})
	return ScheduleRequest{Name: "safe-disk-" + scope + "-" + scriptcatalog.Digest([]byte(machine))[:12], ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: args, Targets: []string{machine}, Cron: fmt.Sprintf("%d %d * * *", minute, hour), Enabled: true, CatchUp: false}, nil
}

func (s *Store) DiskScheduleRunNow(id, digest, key string, apply bool, a AuditEntry) (ScheduleResult, error) {
	var out ScheduleResult
	v, err := s.ScheduleGet(id)
	if err != nil {
		return out, err
	}
	if !scriptcatalog.IsDisk(v.ScriptID) {
		return out, operatorError("BAD_REQUEST", "not a disk schedule")
	}
	if err = humanDiskAdmin(a); err != nil {
		return out, err
	}
	out.Schedule = v
	out.PreviewDigest = "sha256:" + scriptcatalog.Digest(mustScriptJSON(v))
	a.Action = AuditScheduleRunNow
	a.Subject = id
	a.RequestDigest = out.PreviewDigest
	a.OK = true
	a.Detail = "disk schedule run preview"
	if !apply {
		return out, s.RecordAudit(a)
	}
	if key == "" || digest == "" {
		return out, operatorError("BAD_REQUEST", "preview and idempotency key required")
	}
	a.IdempotencyKey = key
	var receipt ScheduleRunNowResponse
	out.JobIDs, err = s.runSchedule(id, s.now().UTC(), true, a, &receipt, digest)
	out.Replayed = receipt.Replayed
	if err != nil {
		a.OK = false
		a.Detail = "disk schedule run rejected"
		_ = s.RecordAudit(a)
	}
	return out, err
}
