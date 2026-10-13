package store

import (
	"context"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// DecideUsageRecommendation only stores intent. It cannot dispatch any job.
// Snooze uses rejected in the ledger, never a new approval state.
func (s *Store) decideUsageRecommendation(binding OpsApproval, decision, reason string, reopen *time.Time, audit AuditEntry) (OpsApproval, error) {
	var out OpsApproval
	if e := humanDiskAdmin(audit); e != nil {
		return out, e
	}
	if binding.Operation != "usage-recommendation-v1" ||
		!usageEnum(decision, "approved", "dismissed", "snoozed") ||
		strings.TrimSpace(reason) == "" ||
		len(reason) > 500 ||
		scriptcatalog.Redact(reason) != reason {
		return out, ErrUsageInvalid
	}
	now := s.now().UTC().Truncate(time.Second)
	if decision == "snoozed" {
		if reopen == nil || !reopen.After(now) {
			return out, ErrUsageInvalid
		}
		reason = "snooze:" + fmtTime(*reopen) + ":" + reason
	} else if reopen != nil || strings.HasPrefix(reason, "snooze:") {
		return out, ErrUsageInvalid
	}
	tx, e := s.beginWrite(context.Background(), "usage_decision")
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	out, e = scanOpsApproval(tx.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, binding.ID))
	if e != nil {
		return out, e
	}
	if out.Operation != binding.Operation ||
		out.MachineID != binding.MachineID ||
		out.PolicyID != binding.PolicyID ||
		out.PolicyRevision != binding.PolicyRevision ||
		out.PolicyDigest != binding.PolicyDigest ||
		out.ItemDigest != binding.ItemDigest ||
		!out.Deadline.Equal(binding.Deadline) {
		return out, ErrUsageConflict
	}
	ledgerState := "rejected"
	if decision == "approved" {
		ledgerState = "approved"
	}
	if out.State == ledgerState && out.DecisionReason == reason && out.DecisionActor == audit.AuthSubject {
		audit.Action = AuditOpsApproval
		audit.Subject = out.ID
		audit.OK = true
		audit.Detail = "unchanged usage decision"
		if e = s.recordAuditTx(tx, audit); e != nil {
			return out, e
		}
		return out, tx.Commit()
	}
	if out.State != "pending" || !out.Deadline.After(now) {
		return out, ErrUsageConflict
	}
	var current int
	if e = tx.QueryRow(`SELECT COUNT(*) FROM ops_policies WHERE id=? AND revision=? AND digest=? AND kind='usage' AND superseded_at IS NULL`,
		out.PolicyID,
		out.PolicyRevision,
		out.PolicyDigest).Scan(&current); e != nil {
		return out, e
	}
	if current != 1 {
		return out, ErrUsageConflict
	}
	result, e := tx.Exec(`UPDATE usage_recommendations SET state=?,reopen_at=? WHERE id=? AND state='open'`, decision, optionalUsageTime(reopen), out.ID)
	if e != nil {
		return out, e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return out, e
	}
	if n != 1 {
		return out, ErrUsageConflict
	}
	_,
		e = tx.Exec(`UPDATE ops_approvals SET state=?,decision_actor=?,decided_at=?,decision_reason=? WHERE id=?`,
		ledgerState,
		audit.AuthSubject,
		fmtTime(now),
		reason,
		out.ID)
	if e != nil {
		return out, e
	}
	out.State = ledgerState
	out.DecisionReason = reason
	out.DecisionActor = audit.AuthSubject
	out.DecidedAt = &now
	audit.Action = AuditOpsApproval
	audit.Subject = out.ID
	audit.MachineID = out.MachineID
	audit.OK = true
	// Only immutable evidence digests and state enter audit; no rationale/labels.
	audit.Detail = string(mustScriptJSON(struct{ ID, State, ItemDigest string }{out.ID, out.State, out.ItemDigest}))
	if e = s.recordAuditTx(tx, audit); e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func optionalUsageTime(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

func (s *Store) DecideUsageRecommendation(binding OpsApproval, decision, reason string, reopen *time.Time, audit AuditEntry) (OpsApproval, error) {
	audit.Reason = ""
	out, err := s.decideUsageRecommendation(binding, decision, reason, reopen, audit)
	if err != nil {
		audit.Action = AuditOpsApproval
		audit.Subject = "usage-recommendation"
		audit.OK = false
		audit.Detail = "usage decision rejected"
		if e := s.RecordAudit(audit); e != nil {
			return out, e
		}
	}
	return out, err
}
