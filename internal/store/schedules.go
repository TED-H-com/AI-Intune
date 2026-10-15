package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"regexp"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/schedulecron"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

type Schedule struct {
	ExecutionMode string          `json:"execution_mode"`
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	ScriptID      string          `json:"script_id"`
	ScriptSHA256  string          `json:"script_sha256"`
	Args          json.RawMessage `json:"args"`
	Targets       []string        `json:"targets"`
	TZ            string          `json:"tz"`
	Cron          string          `json:"cron"`
	Enabled       bool            `json:"enabled"`
	CatchUp       bool            `json:"catch_up"`
	CreatedBy     string          `json:"created_by"`
	CreatedAt     time.Time       `json:"created_at"`
	UpdatedAt     time.Time       `json:"updated_at"`
	Revision      int64           `json:"revision"`
	LastRunAt     *time.Time      `json:"last_run_at"`
	LastJobIDs    []string        `json:"last_job_ids"`
	NextRunAt     time.Time       `json:"next_run_at"`
	PausedReason  string          `json:"paused_reason"`
}

// ScheduleListResponse is the shared wire envelope for schedule lists.
type ScheduleListResponse struct {
	Items []Schedule `json:"items"`
}
type ScheduleRunNowResponse struct {
	JobIDs   []string `json:"job_ids"`
	Replayed bool     `json:"replayed"`
}

type ScheduleRequest struct {
	ID               string          `json:"id,omitempty"`
	Name             string          `json:"name,omitempty"`
	ScriptID         string          `json:"script_id,omitempty"`
	ScriptSHA256     string          `json:"script_sha256,omitempty"`
	Args             json.RawMessage `json:"args,omitempty"`
	Targets          []string        `json:"targets,omitempty"`
	TZ               string          `json:"tz,omitempty"`
	Cron             string          `json:"cron,omitempty"`
	Enabled          bool            `json:"enabled"`
	CatchUp          bool            `json:"catch_up"`
	ExpectedRevision int64           `json:"expected_revision"`
	PreviewDigest    string          `json:"preview_digest,omitempty"`
	Reason           string          `json:"reason"`
}
type ScheduleResult struct {
	Schedule      Schedule `json:"schedule"`
	PreviewDigest string   `json:"preview_digest"`
	JobIDs        []string `json:"job_ids,omitempty"`
	Replayed      bool     `json:"replayed"`
}

const scheduleColumns = `id,name,script_id,script_sha256,args,targets,cron,enabled,catch_up,created_by,created_at,updated_at,revision,last_run_at,last_job_ids,next_run_at,paused_reason,execution_mode,tz`

func scanSchedule(row jobReadScanner) (v Schedule, err error) {
	var args, targets, created, updated, jobs, next string
	var last sql.NullString
	err = row.Scan(&v.ID, &v.Name, &v.ScriptID, &v.ScriptSHA256, &args, &targets, &v.Cron, &v.Enabled, &v.CatchUp, &v.CreatedBy, &created, &updated, &v.Revision, &last, &jobs, &next, &v.PausedReason, &v.ExecutionMode, &v.TZ)
	if err != nil {
		return
	}
	v.Args = json.RawMessage(args)
	if err = json.Unmarshal([]byte(targets), &v.Targets); err != nil {
		return
	}
	if err = json.Unmarshal([]byte(jobs), &v.LastJobIDs); err != nil {
		return
	}
	v.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return
	}
	v.UpdatedAt, err = time.Parse(time.RFC3339Nano, updated)
	if err != nil {
		return
	}
	v.NextRunAt, err = time.Parse(time.RFC3339Nano, next)
	if last.Valid {
		var t time.Time
		t, err = time.Parse(time.RFC3339Nano, last.String)
		v.LastRunAt = &t
	}
	return
}
func (s *Store) ScheduleGet(id string) (Schedule, error) {
	return scanSchedule(s.rdb.QueryRow(`SELECT `+scheduleColumns+` FROM schedules WHERE id=?`, id))
}
func (s *Store) ScheduleList() ([]Schedule, error) {
	rows, e := s.rdb.Query(`SELECT ` + scheduleColumns + ` FROM schedules ORDER BY name LIMIT 1000`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []Schedule{}
	for rows.Next() {
		v, e := scanSchedule(rows)
		if e != nil {
			return nil, e
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

var scheduleName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// ScheduleManage binds preview to the current revision and normalized request.
// The receipt, configuration and audit share the same writer transaction.
func (s *Store) ScheduleManage(req ScheduleRequest, operation string, apply bool, key string, a AuditEntry) (out ScheduleResult, err error) {
	action := "schedule-" + operation + "-preview"
	if apply {
		action = "schedule-" + operation + "-apply"
	}
	a.Action = AuditAction(action)
	a.Subject = req.ID
	a.Reason = req.Reason
	defer func() {
		if err != nil {
			a.OK = false
			a.Detail = "schedule request rejected"
			_ = s.RecordAudit(a)
		}
	}()
	if req.CatchUp {
		return out, scriptBad("catch_up must be false")
	}
	tx, err := s.beginWrite(context.Background(), "schedule_manage")
	if err != nil {
		return
	}
	defer tx.Rollback()
	requestDigest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(req))
	a.RequestDigest = requestDigest
	a.IdempotencyKey = key
	a.At = s.now().UTC()
	if apply {
		if key == "" || len(key) > 200 {
			return out, scriptBad("idempotency key required")
		}
		var op, digest, response string
		e := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, key).Scan(&op, &digest, &response)
		if e == nil {
			if op != action || digest != requestDigest {
				return out, scriptBad("idempotency conflict")
			}
			if err = json.Unmarshal([]byte(response), &out); err != nil {
				return
			}
			if entry, ok := scriptcatalog.Lookup(out.Schedule.ScriptID); !ok {
				return out, scriptBad("unknown script")
			} else if e := scheduleScope(entry, a); e != nil {
				return out, e
			}
			out.Replayed = true
			a.OK = true
			a.Detail = OperatorIdempotencyReplayPrefix + "schedule receipt"
			if err = s.recordAuditTx(tx, a); err != nil {
				return
			}
			err = tx.Commit()
			return
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
	}
	if req.ID == "" && req.ExpectedRevision != 0 {
		return out, operatorError("REVISION_CONFLICT", "new schedule requires revision zero")
	}
	if operation == "set-enabled" && (req.Name != "" || req.ScriptID != "" || req.ScriptSHA256 != "" || req.Args != nil || req.Targets != nil || req.Cron != "" || req.TZ != "") {
		return out, scriptBad("set-enabled only accepts id, enabled, expected_revision and reason")
	}
	var v Schedule
	if req.ID != "" {
		v, err = scanSchedule(tx.QueryRow(`SELECT `+scheduleColumns+` FROM schedules WHERE id=?`, req.ID))
		if err != nil {
			return
		}
		if old, ok := scriptcatalog.Lookup(v.ScriptID); ok {
			if e := scheduleScope(old, a); e != nil {
				return out, e
			}
		}
		if v.Revision != req.ExpectedRevision {
			return out, operatorError("REVISION_CONFLICT", "schedule revision changed")
		}
	}
	if operation == "upsert" {
		if !scheduleName.MatchString(req.Name) || req.CatchUp {
			return out, scriptBad("invalid schedule name or catch_up")
		}
		normalized, entry, e := normalizeScript(ScriptRunRequest{ScriptID: req.ScriptID, ScriptSHA256: req.ScriptSHA256, Args: req.Args, Targets: req.Targets, Reason: req.Reason})
		if e != nil {
			return out, e
		}
		if e = scheduleScope(entry, a); e != nil {
			return out, e
		}
		if _, e = schedulecron.Parse(req.Cron); e != nil {
			return out, scriptBad(e.Error())
		}
		var existing string
		nameErr := tx.QueryRow(`SELECT id FROM schedules WHERE name=? AND id<>?`, req.Name, req.ID).Scan(&existing)
		if nameErr == nil {
			return out, operatorError("REVISION_CONFLICT", "schedule name already exists")
		}
		if !errors.Is(nameErr, sql.ErrNoRows) {
			return out, nameErr
		}
		v.Name = req.Name
		v.ScriptID = req.ScriptID
		v.ScriptSHA256 = req.ScriptSHA256
		v.ExecutionMode = entry.Mode
		v.Args = normalized.Args
		v.Targets = normalized.Targets
		v.TZ = req.TZ
		if v.TZ == "" {
			v.TZ = "UTC"
		}
		if _, e := time.LoadLocation(v.TZ); e != nil {
			return out, scriptBad("invalid timezone")
		}
		v.Cron = strings.Join(strings.Fields(req.Cron), " ")
		v.Enabled = req.Enabled
		v.PausedReason = ""
	} else if operation == "set-enabled" {
		if req.ID == "" {
			return out, scriptBad("schedule id required")
		}
		v.Enabled = req.Enabled
	} else {
		return out, scriptBad("unknown schedule operation")
	}
	entry, exists := scriptcatalog.Lookup(v.ScriptID)
	if !exists {
		return out, scriptBad("unknown script")
	}
	if e := scheduleScope(entry, a); e != nil {
		return out, e
	}
	if operation == "set-enabled" && req.Enabled && (v.PausedReason != "" || v.ExecutionMode == "" || v.ExecutionMode != entry.Mode) {
		return out, scriptBad("re-approve script through upsert")
	}
	if v.Enabled && scriptcatalog.IsDisk(v.ScriptID) {
		var args struct {
			Scope string `json:"scope"`
		}
		_ = json.Unmarshal(v.Args, &args)
		if args.Scope == "root" {
			return out, operatorError("PRECONDITION_FAILED", "root_helper_missing: root schedule requires a reviewed helper-ready target")
		}
	}
	if v.Enabled {
		normalized, _, e := normalizeScript(ScriptRunRequest{ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args, Targets: v.Targets, Reason: req.Reason})
		if e != nil {
			return out, e
		}
		if e = s.diskSafeGateTx(tx, normalized, entry, apply); e != nil {
			return out, e
		}
		if e = validateScriptTargetsTx(tx, normalized, entry); e != nil {
			return out, e
		}
	}
	var reasonErr error
	req.Reason, reasonErr = boundedtext.Reason(req.Reason)
	if reasonErr != nil {
		return out, scriptBad(reasonErr.Error())
	}

	canonical := req
	canonical.PreviewDigest = ""
	canonical.Args = v.Args
	canonical.Targets = v.Targets
	canonical.Cron = v.Cron
	canonical.TZ = v.TZ
	out.PreviewDigest = scriptModeBoundDigest(canonical, entry.Mode)
	if v.LastJobIDs == nil {
		v.LastJobIDs = []string{}
	}
	out.Schedule = v
	if apply {
		if req.PreviewDigest != out.PreviewDigest {
			return out, scriptBad("preview digest mismatch")
		}
		cron, _ := schedulecron.Parse(v.Cron)
		v.NextRunAt = scheduleNext(cron, a.At, v.TZ)
		v.UpdatedAt = a.At
		v.Revision++
		if v.ID == "" {
			var count int
			if err = tx.QueryRow(`SELECT COUNT(*) FROM schedules`).Scan(&count); err != nil {
				return
			}
			if count >= 1000 {
				return out, scriptBad("schedule limit reached")
			}
			v.ID = newID()
			v.CreatedBy = a.AuthSubject
			v.CreatedAt = a.At
			v.LastJobIDs = []string{}
		}
		_, err = tx.Exec(`INSERT INTO schedules (`+scheduleColumns+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET name=excluded.name,script_id=excluded.script_id,script_sha256=excluded.script_sha256,args=excluded.args,targets=excluded.targets,cron=excluded.cron,enabled=excluded.enabled,updated_at=excluded.updated_at,revision=excluded.revision,next_run_at=excluded.next_run_at,paused_reason=excluded.paused_reason,execution_mode=excluded.execution_mode,tz=excluded.tz`, v.ID, v.Name, v.ScriptID, v.ScriptSHA256, string(v.Args), string(mustScriptJSON(v.Targets)), v.Cron, v.Enabled, false, v.CreatedBy, fmtTime(v.CreatedAt), fmtTime(v.UpdatedAt), v.Revision, nil, string(mustScriptJSON(v.LastJobIDs)), fmtTime(v.NextRunAt), v.PausedReason, v.ExecutionMode, v.TZ)
		if err != nil {
			return
		}
		out.Schedule = v
		_, err = tx.Exec(`INSERT INTO operator_idempotency (idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,?,?,'ok',?,?)`, key, action, requestDigest, string(mustScriptJSON(out)), fmtTime(a.At))
		if err != nil {
			return
		}
	}
	a.OK = true
	a.Subject = v.Name
	a.Detail = "schedule configuration"
	if err = s.recordAuditTx(tx, a); err != nil {
		return
	}
	err = tx.Commit()
	return
}

// ResumeSchedules discards missed slots on startup without altering future slots.
func (s *Store) ResumeSchedules(now time.Time) error {
	tx, e := s.beginWrite(context.Background(), "schedule_resume")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	rows, e := tx.Query(`SELECT `+scheduleColumns+` FROM schedules WHERE enabled=1 AND next_run_at<=?`, fmtTime(now))
	if e != nil {
		return e
	}
	var all []Schedule
	for rows.Next() {
		v, e := scanSchedule(rows)
		if e != nil {
			rows.Close()
			return e
		}
		all = append(all, v)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range all {
		if e = s.recordScheduleSkipTx(tx, v, now, "skipped_restart"); e != nil {
			return e
		}
	}

	return tx.Commit()
}
func (s *Store) TickSchedules(now time.Time) error {
	all, e := s.ScheduleList()
	if e != nil {
		return e
	}
	for _, v := range all {
		if v.Enabled && !v.NextRunAt.After(now) {
			if _, e = s.runSchedule(v.ID, now, false, AuditEntry{}, nil); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *Store) ScheduleRunNow(id, key string, a AuditEntry) (out ScheduleRunNowResponse, err error) {
	a.IdempotencyKey = key
	out.JobIDs = []string{}
	out.JobIDs, err = s.runSchedule(id, s.now().UTC(), true, a, &out)
	if out.JobIDs == nil {
		out.JobIDs = []string{}
	}
	if err != nil {
		a.Action = AuditScheduleRunNow
		a.Subject = id
		a.OK = false
		a.Detail = "schedule run rejected"
		_ = s.RecordAudit(a)
	}
	return
}
func (s *Store) runSchedule(id string, now time.Time, manual bool, a AuditEntry, receipt *ScheduleRunNowResponse, binding ...string) (jobs []string, err error) {
	tx, err := s.beginWrite(context.Background(), "schedule_run")
	if err != nil {
		return
	}
	defer tx.Rollback()
	v, err := scanSchedule(tx.QueryRow(`SELECT `+scheduleColumns+` FROM schedules WHERE id=?`, id))
	if err != nil {
		return
	}
	entry, ok := scriptcatalog.Lookup(v.ScriptID)
	if manual {
		if !ok {
			return nil, scriptBad("unknown script")
		}
		if err = scheduleScope(entry, a); err != nil {
			return
		}

	}
	if !manual && (!v.Enabled || v.NextRunAt.After(now)) {
		return nil, nil
	}

	if len(binding) > 0 && binding[0] != "sha256:"+scriptcatalog.Digest(mustScriptJSON(v)) {
		return nil, operatorError("REVISION_CONFLICT", "schedule preview changed")
	}
	requestDigest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(struct{ ID, Principal string }{id, a.AuthSubject}))
	if manual {
		if a.IdempotencyKey == "" || len(a.IdempotencyKey) > 200 {
			return nil, scriptBad("idempotency key required")
		}
		var op, digest, raw string
		e := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, a.IdempotencyKey).Scan(&op, &digest, &raw)
		if e == nil {
			if op != "schedule-run-now" || digest != requestDigest {
				return nil, scriptBad("idempotency conflict")
			}
			if e = json.Unmarshal([]byte(raw), receipt); e != nil {
				return nil, e
			}
			receipt.Replayed = true
			a.At = now
			a.Action = AuditScheduleRunNow
			a.Subject = v.Name
			a.RequestDigest = requestDigest
			a.OK = true
			a.Detail = OperatorIdempotencyReplayPrefix + "manual schedule receipt"
			if e = s.recordAuditTx(tx, a); e != nil {
				return nil, e
			}
			return receipt.JobIDs, tx.Commit()
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return nil, e
		}
		if v.PausedReason != "" {
			return nil, scriptBad("schedule paused")
		}
	}
	commit := func() error {
		if manual {
			receipt.JobIDs = jobs
			if receipt.JobIDs == nil {
				receipt.JobIDs = []string{}
			}
			_, e := tx.Exec(`INSERT INTO operator_idempotency(idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,'schedule-run-now',?,'ok',?,?)`, a.IdempotencyKey, requestDigest, string(mustScriptJSON(receipt)), fmtTime(now))
			if e != nil {
				return e
			}
		}
		return tx.Commit()
	}
	originalPrincipal := a.AuthSubject
	a.At = now
	a.Action = AuditScheduleRun
	a.Subject = v.Name
	a.AuthSubject = "scheduler:" + v.Name
	a.OK = true
	if manual {
		operatorAudit := a
		operatorAudit.AuthSubject = originalPrincipal
		operatorAudit.Action = AuditScheduleRunNow
		operatorAudit.Detail = "manual schedule trigger"
		operatorAudit.RequestDigest = requestDigest
		if err = s.recordAuditTx(tx, operatorAudit); err != nil {
			return
		}
	}
	pauseReason := ""
	if !ok || entry.SHA256 != v.ScriptSHA256 || scriptcatalog.Digest(entry.Bytes) != v.ScriptSHA256 {
		pauseReason = "script_changed"
	} else if v.ExecutionMode == "" || v.ExecutionMode != entry.Mode {
		pauseReason = "mode_changed"
	}
	if pauseReason != "" {
		_, err = tx.Exec(`UPDATE schedules SET enabled=0,paused_reason=?,revision=revision+1,updated_at=? WHERE id=?`, pauseReason, fmtTime(now), id)
		if err != nil {
			return
		}
		a.Detail = pauseReason
		if err = s.recordAuditTx(tx, a); err != nil {
			return
		}
		err = commit()
		return
	}

	slot := v.NextRunAt
	if manual {
		slot = time.Time{}
	}
	if !manual && now.Sub(slot) >= time.Minute {
		if err = s.recordScheduleSkipTx(tx, v, now, "skipped_late"); err != nil {
			return
		}
		err = tx.Commit()
		return
	}
	if !manual {
		result, e := tx.Exec(`INSERT OR IGNORE INTO schedule_slots(schedule_id,slot,outcome) VALUES (?,?,'pending')`, id, fmtTime(slot))
		if e != nil {
			return nil, e
		}
		n, e := result.RowsAffected()
		if e != nil {
			return nil, e
		}
		if n == 0 {
			c, e := schedulecron.Parse(v.Cron)
			if e != nil {
				return nil, e
			}
			if _, e = tx.Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(scheduleNext(c, now, v.TZ)), id); e != nil {
				return nil, e
			}
			return nil, tx.Commit()
		}
	}
	slotKey := fmtTime(slot)
	if manual {
		slotKey = "manual:" + a.IdempotencyKey
	}
	var active int
	err = tx.QueryRow(`SELECT COUNT(*) FROM schedule_jobs sj JOIN jobs j ON j.job_id=sj.job_id WHERE sj.schedule_id=? AND j.state NOT IN (?,?,?,?,?)`, id, deploy.Succeeded, deploy.Failed, deploy.Rejected, deploy.LeaseExpired, deploy.ManualIntervention).Scan(&active)
	if err != nil {
		return
	}
	outcome := "enqueued"
	req := ScriptRunRequest{ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args, Targets: v.Targets, TimeoutSeconds: entry.DefaultTimeout, Reason: "scheduled catalog run"}
	if entry.ID == "disk-deep-report-v1" {
		for _, target := range v.Targets {
			available, e := deepAvailableTx(tx, target, now)
			if e != nil {
				return nil, e
			}
			if !available {
				if manual {
					return nil, operatorError("PRECONDITION_FAILED", "deep report coalesced within six hours")
				}
				active++
			}
		}
	}
	if active > 0 {
		outcome = "skipped_overlap"
	} else if err = s.diskSafeGateTx(tx, req, entry); err != nil {
		if manual {
			return nil, err
		}
		outcome = "skipped_unavailable"
		a.Detail = err.Error()
		err = nil
	} else if err = validateScriptTargetsTx(tx, req, entry); err != nil {
		outcome = "skipped_unavailable"
		err = nil
	} else {
		policy, e := diskSafePolicyTx(tx, req, entry)
		if e != nil {
			return nil, e
		}
		raw := mustScriptJSON(scriptcatalog.Spec{Policy: policy, ExecutionMode: v.ExecutionMode, Kind: scriptcatalog.Kind, ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args})
		for _, target := range v.Targets {
			if entry.ID == "disk-quarantine-expire-v1" {
				var args struct {
					ID     string `json:"policy_id"`
					Digest string `json:"policy_digest"`
				}
				_ = json.Unmarshal(v.Args, &args)
				selection, _, selectionErr := expirySelectionTx(tx, target, args.ID, args.Digest, now)
				if selectionErr != nil {
					return nil, selectionErr
				}
				if len(selection) == 0 {
					continue
				}
			}
			desired, rev, e := createDesiredStateTx(tx, "machine", target, scriptcatalog.Kind, v.ScriptID, string(raw), "operator:"+a.AuthSubject, now)
			if e != nil {
				return nil, e
			}
			job, e := createManagedJobTx(tx, target, desired, rev, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(raw), ExecutionTimeout: entry.DefaultTimeout, Irreversible: entry.ID == "disk-quarantine-expire-v1"}, now)
			if e != nil {
				return nil, e
			}
			if entry.ID == "disk-quarantine-expire-v1" {
				if e = recordExpiryJobTx(tx, job, target, v.Args, now); e != nil {
					return nil, e
				}
			}
			jobs = append(jobs, job)
			if _, e = tx.Exec(`INSERT INTO schedule_jobs VALUES (?,?,?,?)`, job, id, v.Name, slotKey); e != nil {
				return nil, e
			}
			row := a
			row.MachineID = target
			single := req
			single.Targets = []string{target}
			row.Detail = scriptDetail(single, []string{job})
			if e = s.recordAuditTx(tx, row); e != nil {
				return nil, e
			}
		}
	}
	if outcome == "enqueued" && len(jobs) == 0 {
		outcome = "skipped_unavailable"
		a.Detail = "no approved expiry items are due"
	}
	if outcome != "enqueued" {
		if a.Detail == "" {
			a.Detail = outcome
		}
		if err = s.recordAuditTx(tx, a); err != nil {
			return
		}
	}
	if !manual {
		_, err = tx.Exec(`UPDATE schedule_slots SET outcome=? WHERE schedule_id=? AND slot=?`, outcome, id, fmtTime(slot))
	}
	if err != nil {
		return
	}
	c, _ := schedulecron.Parse(v.Cron)
	next := v.NextRunAt
	if !manual {
		next = scheduleNext(c, now, v.TZ)
	}
	if outcome == "enqueued" {
		_, err = tx.Exec(`UPDATE schedules SET last_run_at=?,last_job_ids=?,next_run_at=? WHERE id=?`, fmtTime(now), string(mustScriptJSON(jobs)), fmtTime(next), id)
	} else {
		_, err = tx.Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(next), id)
	}
	if err != nil {
		return
	}
	err = commit()
	return
}

func scheduleScope(e scriptcatalog.Entry, a AuditEntry) error {
	if e.ID == "disk-quarantine-expire-v1" {
		return humanDiskAdmin(a)
	}
	if e.ID != "disk-deep-report-v1" && e.Mode == "read" && (a.AuthCapability == "admin" || strings.HasSuffix(a.AuthCapability, "-admin")) {
		a.AuthCapability = "operate"
	}
	if a.AuthMethod == operatorauth.AuthMethodServiceToken && a.AuthCapability == operatorauth.ServiceScopeOperatorAdmin && (e.Mode == "read" || e.Mode == "write") {
		return nil
	}
	return scriptScope(e, a)
}

// One receipt represents the first missed slot; the bounded audit names the
// discarded range, avoiding unbounded work after a long outage.
func (s *Store) recordScheduleSkipTx(tx dbTx, v Schedule, now time.Time, outcome string) error {
	c, e := schedulecron.Parse(v.Cron)
	if e != nil {
		return e
	}
	next := scheduleNext(c, now, v.TZ)
	result, e := tx.Exec(`INSERT OR IGNORE INTO schedule_slots(schedule_id,slot,outcome) VALUES (?,?,?)`, v.ID, fmtTime(v.NextRunAt), outcome)
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n > 0 {
		detail := outcome + ": " + fmtTime(v.NextRunAt) + " through " + fmtTime(now) + "; next " + fmtTime(next)
		if e = s.recordAuditTx(tx, AuditEntry{At: now, Action: AuditScheduleRun, Subject: v.Name, AuthSubject: "scheduler:" + v.Name, OK: true, Detail: detail}); e != nil {
			return e
		}
	}
	_, e = tx.Exec(`UPDATE schedules SET next_run_at=? WHERE id=?`, fmtTime(next), v.ID)
	return e
}

func scheduleNext(c *schedulecron.Cron, after time.Time, tz string) time.Time {
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	return c.NextIn(after, loc)
}

// ScheduleJobIDs returns a bounded history tied to the immutable schedule ID.
func (s *Store) ScheduleJobIDs(id string) ([]string, error) {
	rows, err := s.rdb.Query(`SELECT sj.job_id FROM schedule_jobs sj JOIN jobs j ON j.job_id=sj.job_id WHERE sj.schedule_id=? ORDER BY j.created_at DESC, sj.job_id LIMIT 100`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}
