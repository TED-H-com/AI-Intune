package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
)

type MachineExecutionPolicy struct {
	model.ExecutionPolicy
	Supported        bool  `json:"agent_supported"`
	ObservedRevision int64 `json:"observed_revision"`
}

func readExecutionPolicy(q operatorRowQuerier, machine string) (p MachineExecutionPolicy, err error) {
	err = q.QueryRow(`SELECT execution_policy,execution_policy_revision,execution_policy_supported,execution_policy_observed_revision FROM machine_registry WHERE machine_id=?`, machine).Scan(&p.Mode, &p.Revision, &p.Supported, &p.ObservedRevision)
	if err == nil {
		err = p.Validate()
	}
	return
}
func (s *Store) MachineExecutionPolicy(machine string) (MachineExecutionPolicy, error) {
	return readExecutionPolicy(s.rdb, machine)
}
func executionAllowedTx(q operatorRowQuerier, machine string) error {
	p, err := readExecutionPolicy(q, machine)
	if err != nil {
		return err
	}
	if p.Mode != model.ExecutionManaged {
		return operatorError("MACHINE_MONITOR_ONLY", "This machine is set to monitor only; execution is blocked.")
	}
	return nil
}
func (s *Store) MachineExecutionAllowed(machine string) error {
	return executionAllowedTx(s.rdb, machine)
}

// SQLite guards cover callers that bypass an operator adapter and future job kinds.
// Install after column migration so legacy databases retain managed behavior.
func installExecutionPolicyGuards(db *sql.DB) error {
	for _, v := range []struct{ name, table, event, extra string }{
		{"execution_approvals_insert", "ops_approvals", "INSERT", ""},
		{"execution_approvals_allow", "ops_approvals", "UPDATE OF state", " AND NEW.state='approved'"},
		{"execution_jobs_insert", "jobs", "INSERT", ""},
		{"execution_jobs_start", "jobs", "UPDATE OF state", " AND NEW.state IN ('claimed','running')"},
		{"execution_sessions_insert", "agent_sessions", "INSERT", ""},
		{"execution_disks_insert", "disk_setup_jobs", "INSERT", ""},
		{"execution_disks_deliver", "disk_setup_jobs", "UPDATE OF state", " AND NEW.state='delivered'"},
		{"execution_signins_insert", "signin_sessions", "INSERT", ""},
		{"execution_signins_start", "signin_sessions", "UPDATE OF state", " AND NEW.state IN ('started','submitted')"},
	} {
		query := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS %s BEFORE %s ON %s WHEN COALESCE((SELECT execution_policy FROM machine_registry WHERE machine_id=NEW.machine_id),'invalid')<>'managed'%s BEGIN SELECT RAISE(ABORT,'machine execution is blocked'); END`, v.name, v.event, v.table, v.extra)
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	for _, event := range []string{"INSERT", "UPDATE"} {
		extra := ""
		if event == "UPDATE" {
			extra = " AND (NEW.targets<>OLD.targets OR NEW.enabled<>0)"
		}
		query := fmt.Sprintf(`CREATE TRIGGER IF NOT EXISTS execution_schedule_%s BEFORE %s ON schedules WHEN EXISTS(SELECT 1 FROM json_each(NEW.targets) t LEFT JOIN machine_registry m ON m.machine_id=t.value WHERE COALESCE(m.execution_policy,'managed')<>'managed')%s BEGIN SELECT RAISE(ABORT,'machine execution is blocked'); END`, strings.ToLower(event), event, extra)
		if _, err := db.Exec(query); err != nil {
			return err
		}
	}
	return nil
}

type ExecutionPolicyRequest struct {
	MachineID, Mode, PreviewDigest, Reason, IdempotencyKey string
	ExpectedRevision                                       int64
	Audit                                                  AuditEntry
}
type ExecutionPolicyResult struct {
	MachineID, Mode, PreviousMode, PreviewDigest string
	Revision                                     int64
	Replayed                                     bool
	ClosedSessions                               []string `json:"-"`
}

func executionPolicyDigest(machine string, p MachineExecutionPolicy, mode, reason string) string {
	raw, _ := json.Marshal(struct {
		Machine, Before, After, Reason string
		Revision                       int64
	}{machine, p.Mode, mode, reason, p.Revision})
	return "sha256:" + scriptcatalog.Digest(raw)
}
func (s *Store) ManageExecutionPolicy(req ExecutionPolicyRequest, apply bool) (out ExecutionPolicyResult, err error) {
	a := req.Audit
	a.Action = AuditMachineExecutionPolicyPreview
	if apply {
		a.Action = AuditMachineExecutionPolicyApply
	}
	a.MachineID = req.MachineID
	a.Subject = "Machine execution policy"
	a.Reason = ""
	a.IdempotencyKey = req.IdempotencyKey
	tx, err := s.beginWrite(context.Background(), "machine_execution_policy")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	a.At = s.now().UTC()
	reject := func(code, detail string) (ExecutionPolicyResult, error) {
		a.OK = false
		a.Detail = detail
		if e := s.recordAuditTx(tx, a); e != nil {
			return out, e
		}
		if e := tx.Commit(); e != nil {
			return out, e
		}
		return out, operatorError(code, detail)
	}
	if a.AuthSubject == "" || (a.AuthMethod != operatorauth.AuthMethodLocalAPI && a.AuthMethod != operatorauth.AuthMethodLocalAccountSession) || a.AuthDecision != string(operatorauth.Authorized) || !(a.AuthCapability == "admin" || strings.HasSuffix(a.AuthCapability, "-admin")) {
		return reject("FORBIDDEN", "Human administrator access is required.")
	}
	if req.Mode != model.ExecutionManaged && req.Mode != model.ExecutionMonitorOnly {
		return reject("BAD_REQUEST", "Choose managed or monitor only.")
	}
	reason, e := boundedtext.Reason(req.Reason)
	if e != nil {
		return reject("BAD_REQUEST", "A reason of at most 500 characters is required.")
	}
	req.Reason = reason
	a.Reason = reason
	raw, _ := json.Marshal(struct {
		Machine, Mode, Digest, Reason string
		Revision                      int64
	}{req.MachineID, req.Mode, req.PreviewDigest, reason, req.ExpectedRevision})
	a.RequestDigest = "sha256:" + scriptcatalog.Digest(raw)
	if apply {
		if req.IdempotencyKey == "" || len(req.IdempotencyKey) > 200 {
			return reject("BAD_REQUEST", "A request key is required.")
		}
		var op, digest, saved string
		e := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, req.IdempotencyKey).Scan(&op, &digest, &saved)
		if e == nil {
			if op != "execution-policy:v1" || digest != a.RequestDigest || json.Unmarshal([]byte(saved), &out) != nil {
				return reject("IDEMPOTENCY_CONFLICT", "This request key belongs to another change.")
			}
			out.Replayed = true
			a.OK = true
			a.Detail = "Machine policy change replayed"
			if err = s.recordAuditTx(tx, a); err != nil {
				return out, err
			}
			return out, tx.Commit()
		}
		if e != sql.ErrNoRows {
			return out, e
		}
	}
	p, err := readExecutionPolicy(tx, req.MachineID)
	if err != nil {
		return out, err
	}
	digest := executionPolicyDigest(req.MachineID, p, req.Mode, reason)
	if apply && (req.ExpectedRevision != p.Revision || req.PreviewDigest != digest) {
		return reject("PREVIEW_STALE", "The policy changed. Preview again.")
	}
	if req.Mode == model.ExecutionMonitorOnly && p.Mode != req.Mode {
		var enrolled sql.NullString
		if e := tx.QueryRow(`SELECT enrolled_at FROM machine_registry WHERE machine_id=?`, req.MachineID).Scan(&enrolled); e != nil {
			return out, e
		}
		if enrolled.Valid && !p.Supported {
			return reject("PRECONDITION_FAILED", "Update this agent to support monitoring-only policy before changing it.")
		}
		var active int
		if e := tx.QueryRow(`SELECT (SELECT count(*) FROM jobs WHERE machine_id=? AND state IN ('not_started','claimed','running','verifying'))+(SELECT count(*) FROM disk_setup_jobs WHERE machine_id=? AND state IN ('pending','delivered'))+(SELECT count(*) FROM signin_sessions WHERE machine_id=? AND state IN ('pending','started','submitted','waiting_for_code'))`, req.MachineID, req.MachineID, req.MachineID).Scan(&active); e != nil {
			return out, e
		}
		if active != 0 {
			return reject("PRECONDITION_FAILED", "Finish or cancel current work before choosing monitor only.")
		}
	}
	out = ExecutionPolicyResult{MachineID: req.MachineID, Mode: req.Mode, PreviousMode: p.Mode, Revision: p.Revision, PreviewDigest: digest}
	if apply {
		if req.Mode == model.ExecutionMonitorOnly {
			if _, err = tx.Exec(`UPDATE schedules SET enabled=0,revision=revision+1,paused_reason='machine_monitor_only' WHERE enabled<>0 AND EXISTS(SELECT 1 FROM json_each(targets) WHERE value=?)`, req.MachineID); err != nil {
				return out, err
			}
		}
		if _, err = tx.Exec(`UPDATE machine_registry SET execution_policy=?,execution_policy_revision=execution_policy_revision+1 WHERE machine_id=? AND execution_policy_revision=?`, req.Mode, req.MachineID, p.Revision); err != nil {
			return out, err
		}
		out.Revision++
		if req.Mode == model.ExecutionMonitorOnly {
			out.ClosedSessions, err = closeOpenAgentSessionsForMachine(tx, req.MachineID, a.At, "Machine changed to monitor only")
			if err != nil {
				return out, err
			}
		}
		saved, _ := json.Marshal(out)
		if _, err = tx.Exec(`INSERT INTO operator_idempotency(idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,'execution-policy:v1',?,'ok',?,?)`, req.IdempotencyKey, a.RequestDigest, string(saved), fmtTime(a.At)); err != nil {
			return out, err
		}
	}
	a.OK = true
	a.Detail = "Machine execution policy: " + p.Mode + " -> " + req.Mode
	if err = s.recordAuditTx(tx, a); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
