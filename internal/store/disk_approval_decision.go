package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// OpsApprovalDecisionRequest contains the immutable facts returned by preview.
// Approvals are human decisions; the request never contains executable arguments.
type OpsApprovalDecisionRequest struct {
	ID             string    `json:"id"`
	Decision       string    `json:"decision"`
	PolicyRevision int64     `json:"policy_revision"`
	PolicyDigest   string    `json:"policy_digest"`
	ItemDigest     string    `json:"item_digest"`
	Deadline       time.Time `json:"deadline"`
	Reason         string    `json:"reason"`
	PreviewDigest  string    `json:"preview_digest,omitempty"`
}
type OpsApprovalDecisionResult struct {
	Approval      OpsApproval                `json:"approval"`
	Request       OpsApprovalDecisionRequest `json:"request"`
	PreviewDigest string                     `json:"preview_digest"`
	Replayed      bool                       `json:"replayed"`
}

func (s *Store) DiskOpsWritesEnabled() bool { return s.diskOpsV2Writes.Load() }
func (s *Store) OpsApproval(id string, now time.Time) (OpsApproval, error) {
	a, err := scanOpsApproval(s.rdb.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return a, operatorError(OperatorCodeMaintenanceNotFound, "approval not found")
	}
	if (a.State == "pending" || a.State == "approved") && !a.Deadline.After(now) {
		a.State = "expired"
	}
	return a, err
}
func (s *Store) DiskPolicyRevision(id string, revision int64) (OpsPolicy, error) {
	p, err := scanOpsPolicy(s.rdb.QueryRow(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at FROM ops_policies WHERE id=? AND revision=? AND kind='disk'`, id, revision))
	if errors.Is(err, sql.ErrNoRows) {
		err = operatorError(OperatorCodeMaintenanceNotFound, "policy revision not found")
	}
	return p, err
}

// ReauthenticateDiskAdmin uses the same password/TOTP checks as account admin
// mutations. Tailnet authority is freshly checked by the HTTP boundary on each
// request; it has no Hub-local password. Credentials are never returned or saved.
func (s *Store) ReauthenticateDiskAdmin(a AuditEntry, password, code string, requireMFA bool) error {
	if err := humanDiskAdmin(a); err != nil {
		return err
	}
	reject := func() error {
		return operatorError("FORBIDDEN", "Reauthentication failed; check your current password and authenticator code.")
	}
	if a.AuthMethod == operatorauth.AuthMethodLocalAPI {
		if password != "" || code != "" {
			return reject()
		}
		return nil
	}
	id := strings.TrimPrefix(a.AuthSubject, "local-user:")
	if id == a.AuthSubject || len(password) > 256 || len(code) > 6 {
		return reject()
	}
	login, err := s.LocalAccountLogin(id)
	if err != nil {
		return reject()
	}
	account, err := s.VerifyPassword(login, password, a.SourceAddr, a)
	if err != nil || account.AccountID != id || account.Role != "admin" {
		return reject()
	}
	enabled, err := s.MFAEnabled(id)
	if err != nil {
		return reject()
	}
	if enabled {
		if err = s.VerifyAdminTOTP(id, a.SourceAddr, code, a); err != nil {
			return reject()
		}
	} else if requireMFA {
		return reject()
	}
	return nil
}

// OpsApprovalDecision is the canonical UI/JSON/MCP preview/apply boundary.
// Scope is checked before replay; the decision, receipt and audit are atomic.
func (s *Store) OpsApprovalDecision(req OpsApprovalDecisionRequest, apply bool, key string, audit AuditEntry) (out OpsApprovalDecisionResult, err error) {
	if apply && req.Decision == "approved" {
		if err = humanDiskAdmin(audit); err != nil {
			return out, err
		}
		var bound int
		if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM ops_manifests WHERE approval_id=?`, req.ID).Scan(&bound); err != nil {
			return out, err
		}
		if bound != 0 {
			return out, operatorError("PRECONDITION_FAILED", "manifest approval requires the exact disk action confirmation")
		}
	}
	return s.opsApprovalDecision(req, apply, key, audit, nil)
}

func (s *Store) opsApprovalDecision(req OpsApprovalDecisionRequest, apply bool, key string, audit AuditEntry, createJob func(dbTx, OpsApproval) (string, error)) (out OpsApprovalDecisionResult, err error) {
	audit.Action = AuditOpsApproval
	audit.Subject = req.ID
	audit.IdempotencyKey = key
	defer func() {
		if err != nil {
			audit.OK = false
			audit.Detail = "approval decision request rejected"
			if ae := s.RecordAudit(audit); ae != nil {
				err = ae
			}
		}
	}()
	if err = humanDiskAdmin(audit); err != nil {
		return out, err
	}
	if apply {
		if err = s.diskWriteScope(audit); err != nil {
			return out, err
		}
	}
	if len(req.Reason) > 500 {
		return out, operatorError("BAD_REQUEST", "decision reason exceeds bound")
	}
	req.Reason = strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, req.Reason))
	if !validJobReadStoredIdentifier(req.ID, 128) || (req.Decision != "approved" && req.Decision != "rejected") || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 || scriptcatalog.Redact(req.Reason) != req.Reason {
		return out, operatorError("BAD_REQUEST", "approval ID, decision and safe reason required")
	}
	tx, err := s.beginWrite(context.Background(), "ops_approval_decision")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	now := s.now().UTC().Truncate(time.Second)
	requestDigest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(struct {
		Actor   string
		Request OpsApprovalDecisionRequest
	}{audit.AuthSubject, req}))
	if createJob != nil {
		requestDigest = "disk-action:" + requestDigest
	}
	audit.RequestDigest = requestDigest
	if apply {
		if key == "" || len(key) > 200 {
			return out, operatorError("BAD_REQUEST", "idempotency key required")
		}
		var op, digest, raw string
		e := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, key).Scan(&op, &digest, &raw)
		if e == nil {
			if op != "ops-approval-decision-v1" || digest != requestDigest {
				return out, operatorError("REVISION_CONFLICT", "idempotency conflict")
			}
			if err = json.Unmarshal([]byte(raw), &out); err != nil {
				return out, err
			}
			out.Replayed = true
			audit.OK = true
			audit.Detail = OperatorIdempotencyReplayPrefix + "approval decision"
			if err = s.recordAuditTx(tx, audit); err != nil {
				return out, err
			}
			return out, tx.Commit()
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
	}
	a, err := scanOpsApproval(tx.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, req.ID))
	if errors.Is(err, sql.ErrNoRows) {
		return out, operatorError(OperatorCodeMaintenanceNotFound, "approval not found")
	}
	if err != nil {
		return out, err
	}
	if a.State != "pending" || !a.Deadline.After(now) {
		return out, operatorError("PRECONDITION_FAILED", "approval is no longer pending or has expired")
	}
	var current int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, a.PolicyID, a.PolicyRevision, a.PolicyDigest).Scan(&current); err != nil {
		return out, err
	}
	if current != 1 {
		return out, operatorError("REVISION_CONFLICT", "approval policy was revoked")
	}
	if apply && (req.PolicyRevision != a.PolicyRevision || req.PolicyDigest != a.PolicyDigest || req.ItemDigest != a.ItemDigest || !req.Deadline.Equal(a.Deadline)) {
		return out, operatorError("PRECONDITION_FAILED", "approval facts differ from preview")
	}
	req.PolicyRevision = a.PolicyRevision
	req.PolicyDigest = a.PolicyDigest
	req.ItemDigest = a.ItemDigest
	req.Deadline = a.Deadline
	originalDigest := req.PreviewDigest
	req.PreviewDigest = ""
	digest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(struct {
		Actor                      string
		Request                    OpsApprovalDecisionRequest
		Machine, Operation, Policy string
	}{audit.AuthSubject, req, a.MachineID, a.Operation, a.PolicyID}))
	if apply && originalDigest != digest {
		return out, operatorError("PRECONDITION_FAILED", "approval preview digest mismatch")
	}
	req.PreviewDigest = digest
	out = OpsApprovalDecisionResult{Approval: a, Request: req, PreviewDigest: digest}
	if apply {
		out.Approval.State = req.Decision
		out.Approval.DecisionReason = req.Reason
		out.Approval.DecisionActor = audit.AuthSubject
		out.Approval.DecidedAt = &now
		if _, err = tx.Exec(`UPDATE ops_approvals SET state=?,decision_actor=?,decided_at=?,decision_reason=? WHERE id=? AND state='pending'`, req.Decision, audit.AuthSubject, fmtTime(now), req.Reason, a.ID); err != nil {
			return out, err
		}
		if req.Decision == "approved" && createJob != nil {
			job, ce := createJob(tx, out.Approval)
			if ce != nil {
				return out, ce
			}
			out.Approval.State = "consumed"
			out.Approval.JobID = job
			out.Approval.ConsumedAt = &now
			if _, err = tx.Exec(`UPDATE ops_approvals SET state='consumed',job_id=?,consumed_at=? WHERE id=? AND state='approved'`, job, fmtTime(now), a.ID); err != nil {
				return out, err
			}
		}
		if _, err = tx.Exec(`INSERT INTO operator_idempotency(idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,'ops-approval-decision-v1',?,'ok',?,?)`, key, requestDigest, string(mustScriptJSON(out)), fmtTime(now)); err != nil {
			return out, err
		}
	}
	audit.MachineID = a.MachineID
	audit.OK = true
	audit.Detail = opsApprovalAuditDetail(out.Approval)
	if !apply {
		audit.Detail = "preview " + audit.Detail
	}
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
