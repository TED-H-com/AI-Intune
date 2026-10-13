package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// OpsApproval contains no paths or executable arguments. It is ledger evidence,
// never a bearer grant. Future adapters must revalidate filesystem facts before
// execution and obtain fresh dispatch admission.
type OpsApproval struct {
	ID             string     `json:"id"`
	State          string     `json:"state"`
	Actor          string     `json:"actor"`
	MachineID      string     `json:"machine_id"`
	Operation      string     `json:"operation"`
	PolicyID       string     `json:"policy_id"`
	PolicyRevision int64      `json:"policy_revision"`
	PolicyDigest   string     `json:"policy_digest"`
	ItemDigest     string     `json:"item_digest"`
	CreatedAt      time.Time  `json:"created_at"`
	Deadline       time.Time  `json:"deadline"`
	DecisionReason string     `json:"decision_reason,omitempty"`
	DecisionActor  string     `json:"decision_actor,omitempty"`
	DecidedAt      *time.Time `json:"decided_at,omitempty"`
	JobID          string     `json:"job_id,omitempty"`
	ConsumedAt     *time.Time `json:"consumed_at,omitempty"`
}

func scanOpsApproval(row interface{ Scan(...any) error }) (OpsApproval, error) {
	var a OpsApproval
	var created, deadline string
	var decided, consumed sql.NullString
	err := row.Scan(&a.ID, &a.State, &a.Actor, &a.MachineID, &a.Operation, &a.PolicyID, &a.PolicyRevision, &a.PolicyDigest, &a.ItemDigest, &created, &deadline, &a.DecisionActor, &decided, &a.JobID, &consumed, &a.DecisionReason)
	a.CreatedAt = parseTime(created)
	a.Deadline = parseTime(deadline)
	if decided.Valid {
		t := parseTime(decided.String)
		a.DecidedAt = &t
	}
	if consumed.Valid {
		t := parseTime(consumed.String)
		a.ConsumedAt = &t
	}
	return a, err
}

const opsApprovalColumns = `id,state,actor,machine_id,operation,policy_id,policy_revision,policy_digest,item_digest,created_at,deadline,COALESCE(decision_actor,''),decided_at,COALESCE(job_id,''),consumed_at,decision_reason`

func (s *Store) OpsApprovals(now time.Time) ([]OpsApproval, error) {
	return s.OpsApprovalsFiltered("", "", "", now)
}
func (s *Store) OpsApprovalsFiltered(state, machine, operation string, now time.Time) ([]OpsApproval, error) {
	if state != "" && state != "pending" && state != "approved" && state != "rejected" && state != "expired" && state != "consumed" {
		return nil, operatorError("BAD_REQUEST", "invalid approval state")
	}
	if machine != "" && !validJobReadStoredIdentifier(machine, 128) {
		return nil, operatorError("BAD_REQUEST", "invalid machine ID")
	}
	if operation != "" && !opsOperationValid(operation) {
		return nil, operatorError("BAD_REQUEST", "invalid operation")
	}
	rows, err := s.rdb.Query(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE (?='' OR CASE WHEN state IN ('pending','approved') AND deadline<=? THEN 'expired' ELSE state END=?) AND (?='' OR machine_id=?) AND (?='' OR operation=?) ORDER BY created_at DESC,id LIMIT 500`, state, fmtTime(now), state, machine, machine, operation, operation)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OpsApproval{}
	for rows.Next() {
		a, e := scanOpsApproval(rows)
		if e != nil {
			return nil, e
		}
		if (a.State == "pending" || a.State == "approved") && !a.Deadline.After(now) {
			a.State = "expired"
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// The closed registry records policy domain and execution eligibility. Adding
// advice never makes it eligible for disk dispatch or approval consumption.
type opsOperationSpec struct {
	PolicyKind string
	Executable bool
}

var opsOperationRegistry = map[string]opsOperationSpec{
	"quarantine": {"disk", true}, "delete": {"disk", true},
	"restore": {"disk", true}, "safe-clean": {"disk", true}, "reject": {"disk", true},
	"usage-recommendation-v1": {"usage", false},
}

func opsOperationValid(op string) bool { _, ok := opsOperationRegistry[op]; return ok }
func diskOperationValid(op string) bool {
	spec, ok := opsOperationRegistry[op]
	return ok && spec.PolicyKind == "disk" && spec.Executable
}
func (s *Store) diskWriteScope(a AuditEntry) error {
	if err := humanDiskAdmin(a); err != nil {
		return err
	}
	if !s.diskOpsV2Writes.Load() {
		return operatorError("PRECONDITION_FAILED", "disk_ops_v2_writes is disabled")
	}
	return nil
}

// ConfigureDiskOpsV2Writes is process configuration, not an operator action.
// It never enables agent delegation or installs execution adapters.
func (s *Store) ConfigureDiskOpsV2Writes(enabled bool) { s.diskOpsV2Writes.Store(enabled) }

// createOpsApproval is a trusted operator-service entry point reserved for
// reviewed adapters. Caller supplies exact policy and report digests.
func (s *Store) createOpsApproval(a OpsApproval, audit AuditEntry) (OpsApproval, error) {
	if a.Operation == "usage-recommendation-v1" {
		if err := humanDiskAdmin(audit); err != nil {
			return a, err
		}
	} else if err := s.diskWriteScope(audit); err != nil {
		return a, err
	}
	if !validJobReadStoredIdentifier(a.ID, 128) || !opsOperationValid(a.Operation) || a.PolicyRevision < 1 || !validLowerSHA256Digest(a.PolicyDigest) || !validLowerSHA256Digest(a.ItemDigest) {
		return a, operatorError("BAD_REQUEST", "invalid approval binding")
	}
	now := s.now().UTC().Truncate(time.Second)
	a.State = "pending"
	a.Actor = audit.AuthSubject
	a.CreatedAt = now
	a.Deadline = now.Add(30 * time.Minute)
	a.DecisionActor = ""
	a.DecidedAt = nil
	a.JobID = ""
	a.ConsumedAt = nil
	tx, err := s.beginWrite(context.Background(), "ops_approval_create")
	if err != nil {
		return a, err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL AND kind=?`, a.PolicyID, a.PolicyRevision, a.PolicyDigest, opsOperationPolicyKind(a.Operation)).Scan(&n); err != nil {
		return a, err
	}
	if n != 1 {
		return a, operatorError("REVISION_CONFLICT", "policy revoked")
	}
	if a.Operation == "usage-recommendation-v1" {
		existing, e := scanOpsApproval(tx.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, a.ID))
		if e == nil {
			if existing.Operation != a.Operation || existing.MachineID != a.MachineID || existing.Actor != a.Actor || existing.PolicyID != a.PolicyID || existing.PolicyRevision != a.PolicyRevision || existing.PolicyDigest != a.PolicyDigest || existing.ItemDigest != a.ItemDigest {
				return a, ErrUsageConflict
			}
			audit.Action = AuditOpsApproval
			audit.Subject = a.ID
			audit.OK = true
			audit.Detail = OperatorIdempotencyReplayPrefix + "usage advice receipt"
			if err = s.recordAuditTx(tx, audit); err != nil {
				return a, err
			}
			return existing, tx.Commit()
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return a, e
		}
	}
	if a.Operation == "usage-recommendation-v1" {
		var r UsageRecommendation
		if err = tx.QueryRow(`SELECT r.id,r.evidence_digest,r.rule_version FROM usage_recommendations r LEFT JOIN usage_recommendation_cycles c ON c.recommendation_id=r.id WHERE COALESCE(c.approval_id,r.id)=? AND r.machine_id=? AND r.state='open'`, a.ID, a.MachineID).Scan(&r.ID, &r.EvidenceDigest, &r.RuleVersion); err != nil {
			return a, err
		}
		if a.ItemDigest != UsageRecommendationItemDigest(r) {
			return a, ErrUsageConflict
		}
	}
	if _, err = tx.Exec(`INSERT INTO ops_approvals(id,state,actor,machine_id,operation,policy_id,policy_revision,policy_digest,item_digest,created_at,deadline) VALUES (?,'pending',?,?,?,?,?,?,?,?,?)`, a.ID, a.Actor, a.MachineID, a.Operation, a.PolicyID, a.PolicyRevision, a.PolicyDigest, a.ItemDigest, fmtTime(now), fmtTime(a.Deadline)); err != nil {
		return a, err
	}
	audit.Action = AuditOpsApproval
	audit.Subject = a.ID
	audit.OK = true
	audit.MachineID = a.MachineID
	audit.Detail = opsApprovalAuditDetail(a)
	if err = s.recordAuditTx(tx, audit); err != nil {
		return a, err
	}
	return a, tx.Commit()
}
func validLowerSHA256Digest(d string) bool {
	return len(d) == 71 && d[:7] == "sha256:" && validLowerSHA256(d[7:])
}

// DecideOpsApproval requires the exact immutable binding again, including the
// policy revision and deadline. Service-token principals fail before any lookup.
func (s *Store) decideOpsApproval(binding OpsApproval, approve bool, audit AuditEntry) (OpsApproval, error) {
	if !diskOperationValid(binding.Operation) {
		return OpsApproval{}, ErrUsageInvalid
	}
	if err := s.diskWriteScope(audit); err != nil {
		return OpsApproval{}, err
	}
	tx, err := s.beginWrite(context.Background(), "ops_approval_decide")
	if err != nil {
		return OpsApproval{}, err
	}
	defer tx.Rollback()
	a, err := scanOpsApproval(tx.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, binding.ID))
	if err != nil {
		return a, err
	}
	now := s.now().UTC().Truncate(time.Second)
	var n int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, a.PolicyID, a.PolicyRevision, a.PolicyDigest).Scan(&n); err != nil {
		return a, err
	}
	if a.State != "pending" {
		return a, operatorError("PRECONDITION_FAILED", "approval is not pending")
	}
	if !a.Deadline.After(now) {
		if _, err = tx.Exec(`UPDATE ops_approvals SET state='expired' WHERE id=? AND state IN ('pending','approved')`, a.ID); err != nil {
			return a, err
		}
		audit.Action = AuditOpsApproval
		audit.Subject = a.ID
		audit.MachineID = a.MachineID
		audit.OK = false
		a.State = "expired"
		audit.Detail = opsApprovalAuditDetail(a)
		if err = s.recordAuditTx(tx, audit); err != nil {
			return a, err
		}
		if err = tx.Commit(); err != nil {
			return a, err
		}
		return a, operatorError("PRECONDITION_FAILED", "approval expired")
	}
	if a.State != "pending" || n != 1 || a.MachineID != binding.MachineID || a.Operation != binding.Operation || a.PolicyID != binding.PolicyID || a.PolicyRevision != binding.PolicyRevision || a.PolicyDigest != binding.PolicyDigest || a.ItemDigest != binding.ItemDigest || !a.Deadline.Equal(binding.Deadline) {
		return a, operatorError("PRECONDITION_FAILED", "approval binding changed or revoked")
	}
	a.State = "rejected"
	if approve {
		a.State = "approved"
	}
	a.DecisionActor = audit.AuthSubject
	a.DecidedAt = &now
	if _, err = tx.Exec(`UPDATE ops_approvals SET state=?,decision_actor=?,decided_at=? WHERE id=?`, a.State, a.DecisionActor, fmtTime(now), a.ID); err != nil {
		return a, err
	}
	audit.Action = AuditOpsApproval
	audit.Subject = a.ID
	audit.OK = true
	audit.MachineID = a.MachineID
	audit.Detail = opsApprovalAuditDetail(a)
	if err = s.recordAuditTx(tx, audit); err != nil {
		return a, err
	}
	return a, tx.Commit()
}

// consumeOpsApproval keeps job creation and consume-once inside one transaction.
// The callback is private and accepts the verified ledger binding; only reviewed
// adapters may wrap it. P2-01 deliberately exposes no arbitrary job factory API.
func (s *Store) consumeOpsApproval(binding OpsApproval, key string, audit AuditEntry, createJob func(dbTx, OpsApproval) (string, error)) (out OpsApproval, err error) {
	if !diskOperationValid(binding.Operation) {
		return out, ErrUsageInvalid
	}
	audit.Action = AuditOpsApproval
	audit.Subject = binding.ID
	audit.IdempotencyKey = key
	defer func() {
		if err != nil {
			audit.OK = false
			audit.Detail = "approval consumption rejected"
			if ae := s.RecordAudit(audit); ae != nil {
				err = ae
			}
		}
	}()

	if err = s.diskWriteScope(audit); err != nil {
		return out, err
	}
	if key == "" || len(key) > 200 {
		return out, operatorError("BAD_REQUEST", "idempotency key required")
	}
	digest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(struct {
		ID, Machine, Operation, Policy, Digest, Items, Actor string
		Revision                                             int64
		Deadline                                             time.Time
	}{binding.ID, binding.MachineID, binding.Operation, binding.PolicyID, binding.PolicyDigest, binding.ItemDigest, audit.AuthSubject, binding.PolicyRevision, binding.Deadline}))
	tx, err := s.beginWrite(context.Background(), "ops_approval_consume")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var op, rd, raw string
	e := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, key).Scan(&op, &rd, &raw)
	audit.Action = AuditOpsApproval
	audit.Subject = binding.ID
	audit.IdempotencyKey = key
	audit.RequestDigest = digest
	if e == nil {
		if op != "ops-approval-consume-v1" || rd != digest {
			return out, operatorError("REVISION_CONFLICT", "idempotency conflict")
		}
		if err = json.Unmarshal([]byte(raw), &out); err != nil {
			return out, err
		}
		audit.OK = true
		audit.Detail = OperatorIdempotencyReplayPrefix + "consumed approval"
		if err = s.recordAuditTx(tx, audit); err != nil {
			return out, err
		}
		return out, tx.Commit()
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	out, err = scanOpsApproval(tx.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, binding.ID))
	if err != nil {
		return out, err
	}
	now := s.now().UTC().Truncate(time.Second)
	if out.State != "approved" {
		return out, operatorError("PRECONDITION_FAILED", "approval is not approved")
	}
	if !out.Deadline.After(now) {
		if _, err = tx.Exec(`UPDATE ops_approvals SET state='expired' WHERE id=? AND state IN ('pending','approved')`, out.ID); err != nil {
			return out, err
		}
		audit.MachineID = out.MachineID
		audit.OK = false
		out.State = "expired"
		audit.Detail = opsApprovalAuditDetail(out)
		if err = s.recordAuditTx(tx, audit); err != nil {
			return out, err
		}
		if err = tx.Commit(); err != nil {
			return out, err
		}
		return out, operatorError("PRECONDITION_FAILED", "approval expired")
	}
	var current int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, out.PolicyID, out.PolicyRevision, out.PolicyDigest).Scan(&current); err != nil {
		return out, err
	}
	if out.State != "approved" || current != 1 || out.DecisionActor == "" || out.MachineID != binding.MachineID || out.Operation != binding.Operation || out.PolicyID != binding.PolicyID || out.PolicyRevision != binding.PolicyRevision || out.PolicyDigest != binding.PolicyDigest || out.ItemDigest != binding.ItemDigest || !out.Deadline.Equal(binding.Deadline) {
		return out, operatorError("PRECONDITION_FAILED", "approval consumed, revoked or binding changed")
	}
	out.JobID, err = createJob(tx, out)
	if err != nil {
		return out, err
	}
	var machine string
	if err = tx.QueryRow(`SELECT machine_id FROM jobs WHERE job_id=?`, out.JobID).Scan(&machine); err != nil {
		return out, err
	}
	if machine != out.MachineID {
		return out, operatorError("PRECONDITION_FAILED", "job machine mismatch")
	}
	out.State = "consumed"
	out.ConsumedAt = &now
	if _, err = tx.Exec(`UPDATE ops_approvals SET state='consumed',job_id=?,consumed_at=? WHERE id=? AND state='approved'`, out.JobID, fmtTime(now), out.ID); err != nil {
		return out, err
	}
	if _, err = tx.Exec(`INSERT INTO operator_idempotency(idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,'ops-approval-consume-v1',?,'ok',?,?)`, key, digest, string(mustScriptJSON(out)), fmtTime(now)); err != nil {
		return out, err
	}
	audit.OK = true
	audit.MachineID = out.MachineID
	audit.Detail = opsApprovalAuditDetail(out)
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// Public trusted-service entry points also retain denial evidence. They expose
// no HTTP authority and never accept service-token approval, including replay.
func (s *Store) CreateOpsApproval(binding OpsApproval, audit AuditEntry) (OpsApproval, error) {
	out, err := s.createOpsApproval(binding, audit)
	if err != nil {
		audit.Action = AuditOpsApproval
		audit.Subject = binding.ID
		audit.OK = false
		audit.Detail = "approval creation rejected"
		if ae := s.RecordAudit(audit); ae != nil {
			return out, ae
		}
	}
	return out, err
}
func (s *Store) DecideOpsApproval(binding OpsApproval, approve bool, audit AuditEntry) (OpsApproval, error) {
	out, err := s.decideOpsApproval(binding, approve, audit)
	if err != nil {
		audit.Action = AuditOpsApproval
		audit.Subject = binding.ID
		audit.OK = false
		audit.Detail = "approval decision rejected"
		if ae := s.RecordAudit(audit); ae != nil {
			return out, ae
		}
	}
	return out, err
}
func opsApprovalAuditDetail(a OpsApproval) string {
	return string(mustScriptJSON(struct {
		ApprovalID     string    `json:"approval_id"`
		Operation      string    `json:"operation"`
		PolicyRevision int64     `json:"policy_revision"`
		PolicyDigest   string    `json:"policy_digest"`
		ItemDigest     string    `json:"item_digest"`
		State          string    `json:"state"`
		JobID          string    `json:"job_id,omitempty"`
		Deadline       time.Time `json:"deadline"`
		DecisionReason string    `json:"decision_reason,omitempty"`
	}{a.ID, a.Operation, a.PolicyRevision, a.PolicyDigest, a.ItemDigest, a.State, a.JobID, a.Deadline, a.DecisionReason}))
}

func opsOperationPolicyKind(op string) string { return opsOperationRegistry[op].PolicyKind }
