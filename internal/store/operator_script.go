package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"sort"
	"strings"
)

type ScriptRunRequest struct {
	ScriptID       string          `json:"script_id"`
	ScriptSHA256   string          `json:"script_sha256"`
	Args           json.RawMessage `json:"args"`
	Targets        []string        `json:"targets"`
	TimeoutSeconds int             `json:"timeout_seconds,omitempty"`
	Reason         string          `json:"reason"`
	PreviewDigest  string          `json:"preview_digest,omitempty"`
}
type ScriptRunResult struct {
	PreviewDigest string   `json:"preview_digest"`
	Targets       []string `json:"targets"`
	JobIDs        []string `json:"job_ids"`
	Replayed      bool     `json:"replayed"`
}

func scriptBad(detail string) error { return operatorError("SCRIPT_INVALID", detail) }
func normalizeScript(req ScriptRunRequest) (ScriptRunRequest, scriptcatalog.Entry, error) {
	e, ok := scriptcatalog.Lookup(req.ScriptID)
	if !ok {
		return req, e, scriptBad("unknown script id")
	}
	if req.ScriptSHA256 != e.SHA256 || scriptcatalog.Digest(e.Bytes) != e.SHA256 {
		return req, e, scriptBad("script sha256 mismatch")
	}
	args, err := e.Validate(req.Args)
	if err != nil {
		return req, e, scriptBad(err.Error())
	}
	req.Args = args
	if req.TimeoutSeconds == 0 {
		req.TimeoutSeconds = e.DefaultTimeout
	}
	if req.TimeoutSeconds < 1 || req.TimeoutSeconds > e.MaxTimeout {
		return req, e, scriptBad("timeout outside catalog bounds")
	}
	if len(req.Targets) < 1 || len(req.Targets) > 50 {
		return req, e, scriptBad("targets must contain 1 to 50 explicit machine IDs")
	}
	req.Targets = append([]string(nil), req.Targets...)
	sort.Strings(req.Targets)
	for i, id := range req.Targets {
		if !validJobReadStoredIdentifier(id, 128) || (i > 0 && req.Targets[i-1] == id) {
			return req, e, scriptBad("invalid or duplicate target")
		}
	}
	if strings.TrimSpace(req.Reason) != req.Reason || req.Reason == "" || len(req.Reason) > 500 || scriptcatalog.Redact(req.Reason) != req.Reason {
		return req, e, scriptBad("reason must be bounded and contain no credentials")
	}
	return req, e, nil
}
func scriptScope(e scriptcatalog.Entry, a AuditEntry) error {
	if scriptcatalog.IsDiskAction(e.ID) {
		return operatorError("PRECONDITION_FAILED", "disk action requires exact manifest approval and dedicated dispatch")
	}
	if e.ID == "disk-deep-report-v1" {
		return humanDiskAdmin(a)
	}
	if a.AuthMethod == operatorauth.AuthMethodServiceToken {
		if e.Mode != "read" {
			return operatorError("SERVICE_TOKEN_READ_SCRIPTS_ONLY", "service tokens require a read-only catalog script")
		}
		if a.AuthCapability != "operate" {
			return operatorError("SCRIPT_SCOPE_REQUIRED", "read scripts require operate")
		}
		return nil
	}
	if e.ID == "disk-safe-preview-v2" && (a.AuthCapability == "admin" || a.AuthCapability == "view") && a.AuthMethod != operatorauth.AuthMethodServiceToken {
		return nil
	}
	if scriptcatalog.IsDiskSafe(e.ID) && e.Mode == "write" {
		return humanDiskAdmin(a)
	}
	if (e.Mode == "write" && (a.AuthCapability == "admin" || strings.HasSuffix(a.AuthCapability, "-admin"))) || (e.Mode == "read" && (a.AuthCapability == "operate" || strings.HasSuffix(a.AuthCapability, "-operate"))) {
		return nil
	}
	return operatorError("SCRIPT_SCOPE_REQUIRED", "script mode requires operate for read or admin for write")
}
func scriptDetail(req ScriptRunRequest, jobs []string) string {
	raw, _ := json.Marshal(struct {
		ID            string `json:"script_id"`
		SHA           string `json:"sha256"`
		Args          string `json:"args_digest"`
		TargetCount   int    `json:"target_count"`
		TargetsDigest string `json:"targets_digest"`
		JobCount      int    `json:"job_count"`
		JobsDigest    string `json:"job_ids_digest"`
	}{req.ScriptID, req.ScriptSHA256, scriptcatalog.Digest(req.Args), len(req.Targets), scriptcatalog.Digest(mustScriptJSON(req.Targets)), len(jobs), scriptcatalog.Digest(mustScriptJSON(jobs))})
	return string(raw)
}

// The mode is resolved by the server, never trusted from the request. Binding
// it prevents a same-hash catalog reclassification from reusing an approval.
func scriptModeBoundDigest(request any, mode string) string {
	return "sha256:" + scriptcatalog.Digest(mustScriptJSON(struct {
		Request       any    `json:"request"`
		ExecutionMode string `json:"execution_mode"`
	}{request, mode}))
}

// ScriptRun validates and creates the complete fanout in a single writer
// transaction with idempotency and one bounded audit row per request. No migration needed.
func (s *Store) ScriptRun(req ScriptRunRequest, apply bool, key string, audit AuditEntry) (out ScriptRunResult, err error) {
	audit.Action = AuditScriptPreview
	if apply {
		audit.Action = AuditScriptApply
	}
	audit.MachineID = ""
	audit.Subject = "script catalog"
	audit.IdempotencyKey = key
	original := req
	entry, exists := scriptcatalog.Lookup(req.ScriptID)
	if audit.AuthMethod == operatorauth.AuthMethodServiceToken && (!exists || entry.Mode != "read") {
		err = operatorError("SERVICE_TOKEN_READ_SCRIPTS_ONLY", "service tokens require a read-only catalog script")
	}
	var e scriptcatalog.Entry
	if err == nil {
		req, e, err = normalizeScript(req)
	}
	if err == nil {
		err = scriptScope(e, audit)
	}
	if err != nil {
		audit.OK = false
		audit.Detail = "script request rejected"
		audit.RequestDigest = scriptcatalog.Digest(mustScriptJSON(original))
		if ae := s.RecordAudit(audit); ae != nil {
			return out, ae
		}
		return out, err
	}
	audit.Reason = req.Reason
	audit.Subject = e.ID
	previewReq := req
	previewReq.PreviewDigest = ""
	digest := scriptModeBoundDigest(previewReq, e.Mode)
	out = ScriptRunResult{PreviewDigest: digest, Targets: req.Targets, JobIDs: []string{}}
	audit.RequestDigest = "script-v2:" + scriptModeBoundDigest(req, e.Mode)
	tx, err := s.beginWrite(context.Background(), "script_run")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	audit.At = s.now().UTC()
	reject := func(detail string) (ScriptRunResult, error) {
		audit.OK = false
		audit.Detail = "script request rejected: " + detail
		if ae := s.recordAuditTx(tx, audit); ae != nil {
			return out, ae
		}
		if ae := tx.Commit(); ae != nil {
			return out, ae
		}
		return out, scriptBad(detail)
	}
	if apply {
		if key == "" || len(key) > 200 {
			return reject("idempotency key required")
		}
		var operation, cachedDigest, response string
		ce := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, key).Scan(&operation, &cachedDigest, &response)
		if ce == nil {
			// Only unversioned historical rows may use compatibility formats.
			// v2 writes never fall back to a digest lacking the approved mode.
			matches := cachedDigest == audit.RequestDigest
			if strings.HasPrefix(cachedDigest, "sha256:") {
				matches = cachedDigest == scriptModeBoundDigest(req, e.Mode) ||
					cachedDigest == "sha256:"+scriptcatalog.Digest(mustScriptJSON(req))
			}
			if operation != "script_v1" || !matches {
				return reject("idempotency conflict")
			}
			if json.Unmarshal([]byte(response), &out) != nil {
				return out, errors.New("invalid script receipt")
			}
			// Correlate the replay audit with the exact stored receipt, including
			// its historical digest version.
			audit.RequestDigest = cachedDigest
			out.Replayed = true
			audit.OK = true
			audit.Detail = OperatorIdempotencyReplayPrefix + scriptDetail(req, out.JobIDs)
			if err = s.recordAuditTx(tx, audit); err != nil {
				return out, err
			}
			return out, tx.Commit()
		}
		if !errors.Is(ce, sql.ErrNoRows) {
			return out, ce
		}
		if req.PreviewDigest != digest {
			return reject("preview digest mismatch")
		}
	}
	if err := s.diskSafeGateTx(tx, req, e, apply); err != nil {
		_, auditErr := reject(err.Error())
		var rejected *OperatorRequestError
		if !errors.As(auditErr, &rejected) {
			return out, auditErr
		}
		return out, err
	}
	if err := validateScriptTargetsTx(tx, req, e); err != nil {
		return reject(err.Error())
	}
	if apply {
		spec := scriptcatalog.Spec{ExecutionMode: e.Mode, Kind: scriptcatalog.Kind, ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: req.Args}
		spec.Policy, err = diskSafePolicyTx(tx, req, e)
		if err != nil {
			return out, err
		}
		raw := mustScriptJSON(spec)
		for _, id := range req.Targets {
			desired, revision, ce := createDesiredStateTx(tx, "machine", id, scriptcatalog.Kind, e.ID, string(raw), "operator:"+audit.AuthSubject, audit.At)
			if ce != nil {
				return out, ce
			}
			job, ce := createManagedJobTx(tx, id, desired, revision, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(raw), ExecutionTimeout: req.TimeoutSeconds}, audit.At)
			if ce != nil {
				return out, ce
			}
			out.JobIDs = append(out.JobIDs, job)
		}
		_, err = tx.Exec(`INSERT INTO operator_idempotency (idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,'script_v1',?,'ok',?,?)`, key, audit.RequestDigest, string(mustScriptJSON(out)), fmtTime(audit.At))
		if err != nil {
			return out, err
		}
	}
	audit.OK = true
	audit.Detail = scriptDetail(req, out.JobIDs)
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}

	return out, tx.Commit()
}
func mustScriptJSON(v any) []byte { raw, _ := json.Marshal(v); return raw }

// recordScriptCompletionTx contains digests and status only, never raw output.
func (s *Store) recordScriptCompletionTx(tx dbTx, jobID string) error {
	var raw, kind, machine, creator, state string
	err := tx.QueryRow(`SELECT d.spec,d.resource_kind,j.machine_id,d.created_by,j.state FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.job_id=?`, jobID).Scan(&raw, &kind, &machine, &creator, &state)
	if err != nil {
		return err
	}
	if kind != scriptcatalog.Kind {
		return nil
	}
	spec, err := scriptcatalog.Decode([]byte(raw))
	if err != nil {
		return err
	}
	var metadata string
	err = tx.QueryRow(`SELECT command FROM verification_results WHERE job_id=? AND rule_id='script_v1_metadata' AND evidence_role=? ORDER BY rowid DESC LIMIT 1`, jobID, JobVerificationRoleExecutor).Scan(&metadata)
	result := scriptcatalog.Result{ExitCode: -1}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if metadata != "" && (json.Unmarshal([]byte(metadata), &result) != nil || !validLowerSHA256(result.StdoutSHA256) || !validLowerSHA256(result.StderrSHA256) || result.Stdout != "" || result.Stderr != "") {
		return errors.New("invalid script completion metadata")
	}
	detail := struct {
		ScriptID string `json:"script_id"`
		SHA      string `json:"sha256"`
		Args     string `json:"args_digest"`
		Job      string `json:"job_id"`
		State    string `json:"state"`
		Exit     int    `json:"exit_code"`
		Out      string `json:"stdout_sha256"`
		Err      string `json:"stderr_sha256"`
	}{spec.ScriptID, spec.ScriptSHA256, scriptcatalog.Digest(spec.Args), jobID, state, result.ExitCode, result.StdoutSHA256, result.StderrSHA256}
	return s.recordAuditTx(tx, AuditEntry{At: s.now().UTC(), Action: AuditScriptComplete, MachineID: machine, Subject: spec.ScriptID, AuthSubject: strings.TrimPrefix(creator, "operator:"), OK: state == string(deploy.Succeeded), Detail: string(mustScriptJSON(detail))})
}

// terminalJobWrite commits terminal status and script audit together.
func (s *Store) terminalJobWrite(ctx context.Context, label, jobID, query string, args ...any) (sql.Result, error) {
	tx, err := s.beginWrite(ctx, label)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(query, args...)
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n > 0 {
		if err = s.recordScriptCompletionTx(tx, jobID); err != nil {
			return nil, err
		}
	}
	return res, tx.Commit()
}

func (s *Store) scriptEvidenceReady(jobID string) (required, ready bool, err error) {
	var kind, raw, machine string
	err = s.rdb.QueryRow(`SELECT d.resource_kind,d.spec,j.machine_id FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.job_id=?`, jobID).Scan(&kind, &raw, &machine)
	if err != nil {
		return false, false, err
	}
	if kind != scriptcatalog.Kind {
		return false, false, nil
	}
	spec, err := scriptcatalog.Decode([]byte(raw))
	if err != nil {
		return true, false, nil
	}
	var count int
	err = s.rdb.QueryRow(`SELECT COUNT(*) FROM verification_results WHERE job_id=? AND machine_id=? AND producer_kind=? AND producer_id=? AND evidence_role=? AND authority=? AND rule_id=? AND command=? AND exit_code=0 AND passed=1`, jobID, machine, JobVerificationProducerExecutorAgent, machine, JobVerificationRoleExecutor, JobVerificationAuthorityMachineLease, scriptcatalog.Kind, spec.ScriptID).Scan(&count)
	if err != nil || count == 0 {
		return true, false, err
	}
	var metadata string
	err = s.rdb.QueryRow(`SELECT command FROM verification_results WHERE job_id=? AND machine_id=? AND producer_kind=? AND producer_id=? AND evidence_role=? AND authority=? AND rule_id='script_v1_metadata' AND exit_code=0 AND passed=1 ORDER BY rowid DESC LIMIT 1`, jobID, machine, JobVerificationProducerExecutorAgent, machine, JobVerificationRoleExecutor, JobVerificationAuthorityMachineLease).Scan(&metadata)
	if errors.Is(err, sql.ErrNoRows) {
		return true, false, nil
	}
	if err != nil {
		return true, false, err
	}
	var result scriptcatalog.Result
	ready = json.Unmarshal([]byte(metadata), &result) == nil && validLowerSHA256(result.StdoutSHA256) && validLowerSHA256(result.StderrSHA256) && result.Stdout == "" && result.Stderr == "" && result.ExitCode == 0 && !result.TimedOut && result.DurationMS >= 0
	return true, ready, nil
}

func validateScriptTargetsTx(tx dbTx, req ScriptRunRequest, e scriptcatalog.Entry) error {
	var failures []string
	for _, id := range req.Targets {
		var name, osName string
		var retired, checkin sql.NullString
		var enabled, capable sql.NullBool
		ge := tx.QueryRow(`SELECT COALESCE(NULLIF(m.display_name,''),m.machine_id),COALESCE(m.os,''),m.retired_at,c.sent_at,c.jobs_enabled,cap.supported
   FROM machine_registry m LEFT JOIN machine_checkins c ON c.rowid=(SELECT rowid FROM machine_checkins WHERE machine_id=m.machine_id ORDER BY received_at DESC,rowid DESC LIMIT 1)
   LEFT JOIN machine_job_capabilities cap ON cap.machine_id=c.machine_id AND cap.sent_at=c.sent_at AND cap.capability=? WHERE m.machine_id=?`, scriptcatalog.Kind, id).Scan(&name, &osName, &retired, &checkin, &enabled, &capable)
		if errors.Is(ge, sql.ErrNoRows) {
			failures = append(failures, id+": target not found")
			continue
		}
		if ge != nil {
			return ge
		}
		var reasons []string
		if retired.Valid {
			reasons = append(reasons, "retired")
		}
		if !checkin.Valid {
			reasons = append(reasons, "no check-in yet")
		} else {
			if !enabled.Valid || !enabled.Bool {
				reasons = append(reasons, "jobs disabled in latest check-in")
			}
			if !capable.Valid || !capable.Bool {
				reasons = append(reasons, "script_v1 capability not advertised in latest check-in")
			}
		}
		platformOS, _, err := latestProfileAssignmentPlatformIdentity(tx, id, osName, "")
		if err != nil {
			return err
		}
		family := scriptcatalog.OSFamily(platformOS)
		if !e.AllowsOS(family) {
			reasons = append(reasons, fmt.Sprintf("OS '%s' (family '%s') not allowed for this script (allowed: %s)", osName, family, strings.Join(e.AllowedOS, ", ")))
		}
		rows, err := tx.Query(`SELECT j.state,COALESCE(d.resource_kind,'unknown') FROM jobs j LEFT JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.machine_id=? AND j.state NOT IN (?,?,?,?,?) ORDER BY j.created_at,j.job_id`, id, deploy.Succeeded, deploy.Failed, deploy.Rejected, deploy.LeaseExpired, deploy.ManualIntervention)
		if err != nil {
			return err
		}
		var active int
		var jobs []string
		for rows.Next() {
			var state, kind string
			if err := rows.Scan(&state, &kind); err != nil {
				rows.Close()
				return err
			}
			active++
			if len(jobs) < 3 {
				jobs = append(jobs, state+"/"+kind)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
		if active > 0 {
			reasons = append(reasons, fmt.Sprintf("%d active job(s) (%s)", active, strings.Join(jobs, ", ")))
		}
		if len(reasons) > 0 {
			failures = append(failures, name+": "+strings.Join(reasons, "; "))
		}
	}
	if len(failures) > 0 {
		return scriptBad(strings.Join(failures, "\n"))
	}
	return nil
}
