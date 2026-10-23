package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"time"
	"unicode"

	"github.com/teddashh/AI-Intune/internal/model"
)

type DiskOwnership struct {
	MachineID        string                      `json:"machine_id"`
	Scope            string                      `json:"scope"`
	State            string                      `json:"state"`
	TransitionNonce  string                      `json:"transition_nonce,omitempty"`
	Revision         int64                       `json:"revision"`
	ChangedAt        time.Time                   `json:"changed_at"`
	Observation      *model.DiskTimerObservation `json:"observation,omitempty"`
	DisableCommand   string                      `json:"disable_command"`
	HubScheduleReady bool                        `json:"hub_schedule_ready"`
	RootHelperReady  bool                        `json:"root_helper_ready"`
	HandoffBlockers  []string                    `json:"handoff_blockers"`
	EnableCommand    string                      `json:"enable_command"`
}

func DiskTimerCommand(scope string, enable bool) string {
	verb := "disable --now"
	if enable {
		verb = "enable --now"
	}
	if scope == "root" {
		return "sudo bash -c 'systemctl " + verb + " disk-clean-root.timer'"
	}
	return "systemctl --user " + verb + " disk-clean.timer"
}

func (s *Store) DiskOwnershipGet(machine, scope string) (DiskOwnership, error) {
	out := DiskOwnership{MachineID: machine, Scope: scope, State: "local-owned", DisableCommand: DiskTimerCommand(scope, false), EnableCommand: DiskTimerCommand(scope, true)}
	if scope != "root" && scope != "user" {
		return out, operatorError("BAD_REQUEST", "invalid disk scope")
	}
	if _, err := s.GetMachine(machine); err != nil {
		return out, err
	}
	var at string
	err := s.rdb.QueryRow(`SELECT state,revision,changed_at,transition_nonce FROM disk_ownership WHERE machine_id=? AND scope=?`, machine, scope).Scan(&out.State, &out.Revision, &at, &out.TransitionNonce)
	if err != nil && err != sql.ErrNoRows {
		return out, err
	}
	out.ChangedAt = parseTime(at)
	var raw string
	err = s.rdb.QueryRow(`SELECT body FROM disk_timer_observations WHERE machine_id=? AND scope=? ORDER BY receipt_seq DESC LIMIT 1`, machine, scope).Scan(&raw)
	if err == nil {
		var o model.DiskTimerObservation
		if json.Unmarshal([]byte(raw), &o) == nil {
			out.Observation = &o
		}
	}
	if err != nil && err != sql.ErrNoRows {
		return out, err
	}
	var ready int
	entry, _ := scriptcatalog.Lookup("disk-safe-clean-v2")
	err = s.rdb.QueryRow(`SELECT COUNT(*) FROM schedules s JOIN ops_policies p ON p.id=json_extract(s.args,'$.policy_id') AND p.digest=json_extract(s.args,'$.policy_digest') AND p.superseded_at IS NULL WHERE s.script_id='disk-safe-clean-v2' AND s.script_sha256=? AND s.execution_mode='write' AND s.enabled=0 AND json_extract(s.args,'$.scope')=? AND EXISTS(SELECT 1 FROM json_each(s.targets) WHERE value=?)`, entry.SHA256, scope, machine).Scan(&ready)
	if err != nil {
		return out, err
	}
	out.HubScheduleReady = ready > 0
	out.HandoffBlockers = []string{}
	if !out.HubScheduleReady {
		out.HandoffBlockers = append(out.HandoffBlockers, "Prepare a disabled Hub apply schedule with the current policy and script.")
	}
	if !s.DiskOpsWritesEnabled() {
		out.HandoffBlockers = append(out.HandoffBlockers, "Enable the Hub disk writes flag before handoff.")
	}
	if scope == "root" {
		out.HandoffBlockers = append(out.HandoffBlockers, "Admin-installed reviewed root helper unavailable; scope stays local-owned.")
	}
	if out.Observation == nil || !out.Observation.Known || out.Observation.ReceivedAt.After(s.now()) || s.now().Sub(out.Observation.ReceivedAt) > 15*time.Minute {
		out.HandoffBlockers = append(out.HandoffBlockers, "A fresh known local timer observation is required.")
	}
	canary, e := s.DiskCanaryGet(machine, scope, s.now())
	if e != nil {
		return out, e
	}
	if !canary.Satisfied {
		out.HandoffBlockers = append(out.HandoffBlockers, "Canary comparison incomplete; explicit override with reason is available.")
	}
	if out.State != "local-owned" {
		out.EnableCommand = ""
	}
	return out, nil
}

type DiskOwnershipRequest struct {
	MachineID        string    `json:"machine_id"`
	Scope            string    `json:"scope"`
	Action           string    `json:"action"`
	ExpectedRevision int64     `json:"expected_revision"`
	Reason           string    `json:"reason"`
	OverrideCanary   bool      `json:"override_canary"`
	ExpiresAt        time.Time `json:"expires_at"`
	PreviewDigest    string    `json:"preview_digest"`
}
type DiskOwnershipResult struct {
	Ownership     DiskOwnership `json:"ownership"`
	PreviewDigest string        `json:"preview_digest"`
	ExpiresAt     time.Time     `json:"expires_at"`
	Replayed      bool          `json:"replayed"`
}

func (s *Store) DiskOwnershipManage(req DiskOwnershipRequest, apply bool, key string, a AuditEntry) (DiskOwnershipResult, error) {
	if strings.TrimSpace(req.Reason) != "" {
		normalizedReason, reasonErr := boundedtext.Reason(req.Reason)
		if reasonErr != nil {
			return DiskOwnershipResult{}, operatorError(OperatorCodeReasonRequired, reasonErr.Error())
		}
		req.Reason = normalizedReason
	}

	var out DiskOwnershipResult
	if err := humanDiskAdmin(a); err != nil {
		return out, err
	}
	if req.Action != "handoff" && req.Action != "rollback" {
		return out, operatorError("BAD_REQUEST", "invalid ownership action")
	}
	req.Reason = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, req.Reason))
	if len([]rune(req.Reason)) > 500 || !validAuditReason(req.Reason) {
		return out, operatorError("BAD_REQUEST", "safe bounded reason required")
	}
	if req.Reason == "" {
		return out, operatorError("BAD_REQUEST", "reason required")
	}
	now := s.now().UTC()
	if !apply {
		req.ExpiresAt = now.Add(30 * time.Minute)
	}
	supplied := req.PreviewDigest
	req.PreviewDigest = ""
	raw, _ := json.Marshal(req)
	out.PreviewDigest = "sha256:" + scriptcatalog.Digest(raw)
	out.ExpiresAt = req.ExpiresAt
	if apply && (key == "" || supplied != out.PreviewDigest) {
		return out, operatorError("PRECONDITION_FAILED", "fresh bound preview and idempotency key required")
	}
	current, err := s.DiskOwnershipGet(req.MachineID, req.Scope)
	if err != nil {
		return out, err
	}
	out.Ownership = current
	tx, err := s.beginWrite(context.Background(), "disk_ownership_manage")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if err = executionAllowedTx(tx, req.MachineID); err != nil {
		return out, err
	}
	if apply {
		var digest, body string
		err = tx.QueryRow(`SELECT digest,body FROM disk_handoff_receipts WHERE actor=? AND idempotency_key=?`, a.AuthSubject, key).Scan(&digest, &body)
		if err == nil {
			if digest != out.PreviewDigest {
				return out, operatorError("REVISION_CONFLICT", "idempotency key conflict")
			}
			err = json.Unmarshal([]byte(body), &out)
			out.Replayed = true
			if current.State != "local-owned" {
				out.Ownership.EnableCommand = ""
			}
			if err != nil {
				return out, err
			}
			a.Action = AuditAction("disk_ownership_" + req.Action)
			a.MachineID = req.MachineID
			a.Subject = req.Scope
			a.RequestDigest = out.PreviewDigest
			a.IdempotencyKey = key
			a.OK = true
			a.Detail = "idempotent replay"
			if err = s.recordAuditTx(tx, a); err != nil {
				return out, err
			}
			return out, tx.Commit()
		}
		if err != sql.ErrNoRows {
			return out, err
		}
	}
	if apply && (!req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(30*time.Minute))) {
		return out, operatorError("PRECONDITION_FAILED", "preview expired")
	}
	var revision int64
	var state string
	err = tx.QueryRow(`SELECT revision,state FROM disk_ownership WHERE machine_id=? AND scope=?`, req.MachineID, req.Scope).Scan(&revision, &state)
	if err != nil && err != sql.ErrNoRows {
		return out, err
	}
	if err == sql.ErrNoRows {
		state = "local-owned"
	}
	if revision != req.ExpectedRevision {
		return out, operatorError("REVISION_CONFLICT", "ownership changed")
	}
	if req.Action == "handoff" {
		if !s.DiskOpsWritesEnabled() {
			return out, operatorError("PRECONDITION_FAILED", "disk_ops_v2_writes is disabled")
		}
		if state != "local-owned" && state != "rolled-back" && state != "handoff-pending" {
			return out, operatorError("PRECONDITION_FAILED", "scope already hub-owned")
		}
		var supported sql.NullBool
		e := tx.QueryRow(`SELECT cap.supported FROM machine_checkins c LEFT JOIN machine_job_capabilities cap ON cap.machine_id=c.machine_id AND cap.sent_at=c.sent_at AND cap.capability='disk_ops_v2' WHERE c.machine_id=? ORDER BY c.received_at DESC,c.rowid DESC LIMIT 1`, req.MachineID).Scan(&supported)
		if e != nil && e != sql.ErrNoRows {
			return out, e
		}
		if !supported.Valid || !supported.Bool {
			return out, operatorError("PRECONDITION_FAILED", "target does not advertise disk_ops_v2")
		}
		if req.Scope == "root" {
			return out, operatorError("PRECONDITION_FAILED", "admin-installed root helper unavailable; scope stays local-owned")
		}
		var ready int
		err = tx.QueryRow(`SELECT COUNT(*) FROM schedules WHERE script_id='disk-safe-clean-v2' AND execution_mode='write' AND script_sha256=? AND enabled=0 AND EXISTS(SELECT 1 FROM ops_policies p WHERE p.id=json_extract(schedules.args,'$.policy_id') AND p.digest=json_extract(schedules.args,'$.policy_digest') AND p.superseded_at IS NULL) AND json_extract(args,'$.scope')=? AND EXISTS(SELECT 1 FROM json_each(targets) WHERE value=?)`, func() string { e, _ := scriptcatalog.Lookup("disk-safe-clean-v2"); return e.SHA256 }(), req.Scope, req.MachineID).Scan(&ready)
		if err != nil {
			return out, err
		}
		if ready == 0 {
			return out, operatorError("PRECONDITION_FAILED", "disabled Hub apply schedule must be ready")
		}
		if current.Observation == nil || !current.Observation.Known || current.Observation.ReceivedAt.After(now) || now.Sub(current.Observation.ReceivedAt) > 15*time.Minute {
			return out, operatorError("PRECONDITION_FAILED", "fresh known local timer observation required")
		}
		canary, e := s.DiskCanaryGet(req.MachineID, req.Scope, now)
		if e != nil {
			return out, e
		}
		if !canary.Satisfied && !req.OverrideCanary {
			return out, operatorError("PRECONDITION_FAILED", "canary comparison incomplete; explicit override with reason required")
		}

	}
	if !apply {
		return out, nil
	}
	next := "handoff-pending"
	if req.Action == "rollback" {
		next = "rollback-pending"
		if _, err = tx.Exec(`UPDATE schedules SET enabled=0,revision=revision+1 WHERE script_id='disk-safe-clean-v2' AND json_extract(args,'$.scope')=? AND EXISTS(SELECT 1 FROM json_each(targets) WHERE value=?) AND enabled=1`, req.Scope, req.MachineID); err != nil {
			return out, err
		}
	}
	nonce := ""
	if next == "handoff-pending" {
		var random [32]byte
		if _, err = rand.Read(random[:]); err != nil {
			return out, err
		}
		nonce = hex.EncodeToString(random[:])
	}
	a.Action = AuditAction("disk_ownership_" + req.Action)
	a.MachineID = req.MachineID
	a.Subject = req.Scope
	a.RequestDigest = out.PreviewDigest
	a.IdempotencyKey = key
	a.OK = true
	a.Detail = next + "; reason=" + req.Reason
	if req.OverrideCanary {
		a.Detail += "; canary explicitly overridden"
	}
	if err = s.recordAuditTx(tx, a); err != nil {
		return out, err
	}
	if next == "rollback-pending" {
		// Queued work has no executor. Claimed/running work must finish or be reaped;
		// do not manufacture a terminal state while an executor may still be active.
		if _, err = tx.Exec(`UPDATE jobs SET state='rejected',terminal_at=?,lease_token=NULL,lease_expires_at=NULL WHERE machine_id=? AND state='not_started' AND desired_id IN (SELECT desired_id FROM desired_state WHERE resource_kind='script_v1' AND resource_id='disk-safe-clean-v2' AND json_extract(spec,'$.args.scope')=?)`, fmtTime(now), req.MachineID, req.Scope); err != nil {
			return out, err
		}
	}
	if _, err = tx.Exec(`INSERT INTO disk_ownership(machine_id,scope,state,revision,changed_at,transition_nonce) VALUES (?,?,?,?,?,?) ON CONFLICT(machine_id,scope) DO UPDATE SET state=excluded.state,revision=excluded.revision,changed_at=excluded.changed_at,transition_nonce=excluded.transition_nonce`, req.MachineID, req.Scope, next, revision+1, diskReceiptTime(now), nonce); err != nil {
		return out, err
	}
	out.Ownership.State = next
	out.Ownership.Revision = revision + 1
	out.Ownership.ChangedAt = now
	out.Ownership.TransitionNonce = nonce
	out.Ownership.EnableCommand = ""
	if next == "rollback-pending" {
		if err = s.finishDiskRollbackTx(tx, req.MachineID, req.Scope, now); err != nil {
			return out, err
		}
		var at string
		if err = tx.QueryRow(`SELECT state,revision,changed_at FROM disk_ownership WHERE machine_id=? AND scope=?`, req.MachineID, req.Scope).Scan(&out.Ownership.State, &out.Ownership.Revision, &at); err != nil {
			return out, err
		}
		out.Ownership.ChangedAt = parseTime(at)
		if out.Ownership.State == "local-owned" {
			out.Ownership.EnableCommand = DiskTimerCommand(req.Scope, true)
		}
	}
	body, _ := json.Marshal(out)
	if _, err = tx.Exec(`INSERT INTO disk_handoff_receipts(actor,idempotency_key,digest,body) VALUES (?,?,?,?)`, a.AuthSubject, key, out.PreviewDigest, string(body)); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
