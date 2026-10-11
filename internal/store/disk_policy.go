package store

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/maintenance"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// DiskPolicy is a closed, versioned contract. ProtectPaths adds protections;
// built-in credentials/backups, generated images, models, user data and all
// repositories are unconditional and cannot be overridden by this document.
type DiskPolicy struct {
	SchemaVersion     int             `json:"schema_version"`
	SafeTier          DiskSafeTier    `json:"safe_tier"`
	ProtectPaths      []string        `json:"protect_paths"`
	Thresholds        DiskThresholds  `json:"thresholds"`
	QuarantineTTLDays int             `json:"quarantine_ttl_days"`
	ScanBudgets       DiskScanBudgets `json:"scan_budgets"`
}
type DiskSafeTier struct {
	UserTmpMinDays int    `json:"user_tmp_min_days"`
	VarTmpMinDays  int    `json:"var_tmp_min_days"`
	DockerMinHours int    `json:"docker_min_hours"`
	DockerMode     string `json:"docker_mode"`
	JournaldMaxMiB int    `json:"journald_max_mib"`
	CargoMinDays   int    `json:"cargo_min_days"`
	UVMode         string `json:"uv_mode"`
	NPMMode        string `json:"npm_mode"`
	ToolCacheMode  string `json:"tool_cache_mode"`
}
type DiskThresholds struct {
	WarnPercent            int `json:"warn_percent"`
	CriticalPercent        int `json:"critical_percent"`
	DeepReportAbovePercent int `json:"deep_report_above_percent"`
}
type DiskScanBudgets struct {
	MaxItems   int `json:"max_items"`
	MaxEntries int `json:"max_entries"`
	MaxSeconds int `json:"max_seconds"`
}

// DiskProtectionRules is the mandatory adapter protection contract, separate
// from caller-controlled policy JSON. Returned slices are copies.
type DiskProtectionRules struct {
	BuiltInNames     []string `json:"built_in_names"`
	ProtectedClasses []string `json:"protected_classes"`
	AdditivePaths    []string `json:"additive_paths"`
}

var diskBuiltInNames = append([]string(nil), maintenance.BuiltinProtect...)

func (p DiskPolicy) Protections() DiskProtectionRules {
	return DiskProtectionRules{append([]string{}, diskBuiltInNames...), []string{"credentials", "credential-backups", "~/.codex/generated_images", "active-models", "user-data", "all-repository-roots", "open-descriptors", "locks"}, append([]string{}, p.ProtectPaths...)}
}

func DefaultDiskPolicy() DiskPolicy {
	return DiskPolicy{1, DiskSafeTier{10, 14, 168, "dangling-and-build-cache", 500, 30, "lock-aware-prune", "verify-only", "native-gc-holder-aware"}, []string{}, DiskThresholds{85, 93, 80}, 7, DiskScanBudgets{500, 200000, 600}}
}
func CanonicalDiskPolicy(raw json.RawMessage) (DiskPolicy, json.RawMessage, string, error) {
	var p DiskPolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, nil, "", operatorError("BAD_REQUEST", "invalid disk policy JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return p, nil, "", operatorError("BAD_REQUEST", "policy must be one JSON document")
	}
	t := p.SafeTier
	b := p.ScanBudgets
	h := p.Thresholds
	if p.SchemaVersion != 1 || p.QuarantineTTLDays != 7 || t.UserTmpMinDays < 10 || t.UserTmpMinDays > 3650 || t.VarTmpMinDays < 14 || t.VarTmpMinDays > 3650 || t.DockerMinHours < 168 || t.DockerMinHours > 87600 || t.CargoMinDays < 30 || t.CargoMinDays > 3650 || t.JournaldMaxMiB < 500 || t.JournaldMaxMiB > 1048576 || t.DockerMode != "dangling-and-build-cache" || t.UVMode != "lock-aware-prune" || t.NPMMode != "verify-only" || t.ToolCacheMode != "native-gc-holder-aware" || h.DeepReportAbovePercent < 1 || h.DeepReportAbovePercent >= h.WarnPercent || h.WarnPercent >= h.CriticalPercent || h.CriticalPercent > 100 || b.MaxItems < 1 || b.MaxItems > 500 || b.MaxEntries < 1 || b.MaxEntries > 200000 || b.MaxSeconds < 1 || b.MaxSeconds > 600 || len(p.ProtectPaths) > 100 {
		return p, nil, "", operatorError("BAD_REQUEST", "disk policy outside safe bounds")
	}
	p.ProtectPaths = append([]string{}, p.ProtectPaths...)
	sort.Strings(p.ProtectPaths)
	for i, v := range p.ProtectPaths {
		if len(v) > 1024 || !strings.HasPrefix(v, "/") || path.Clean(v) != v || strings.ContainsAny(v, "\x00\r\n") || scriptcatalog.Redact(v) != v || (i > 0 && p.ProtectPaths[i-1] == v) {
			return p, nil, "", operatorError("BAD_REQUEST", "invalid or duplicate additive protect path")
		}
	}
	canonical := mustScriptJSON(p)
	return p, canonical, "sha256:" + scriptcatalog.Digest(canonical), nil
}

type OpsPolicy struct {
	ID           string          `json:"id"`
	Kind         string          `json:"kind"`
	Revision     int64           `json:"revision"`
	Body         json.RawMessage `json:"body"`
	Digest       string          `json:"digest"`
	CreatedBy    string          `json:"created_by"`
	CreatedAt    time.Time       `json:"created_at"`
	SupersededAt *time.Time      `json:"superseded_at,omitempty"`
}
type DiskPolicyRequest struct {
	ID               string          `json:"id"`
	Body             json.RawMessage `json:"body"`
	ExpectedRevision *int64          `json:"expected_revision"`
	ExpiresAt        time.Time       `json:"expires_at,omitempty"`
	PreviewDigest    string          `json:"preview_digest,omitempty"`
	Reason           string          `json:"reason"`
}
type DiskPolicyResult struct {
	Policy           OpsPolicy       `json:"policy"`
	ExpectedRevision int64           `json:"expected_revision"`
	ExpiresAt        time.Time       `json:"expires_at"`
	PreviewDigest    string          `json:"preview_digest"`
	Replayed         bool            `json:"replayed"`
	Warnings         []string        `json:"warnings"`
	PreviousBody     json.RawMessage `json:"previous_body,omitempty"`
}

func humanDiskAdmin(a AuditEntry) error {
	if a.AuthSubject == "" || a.AuthDecision != string(operatorauth.Authorized) || (a.AuthMethod != operatorauth.AuthMethodLocalAccountSession && a.AuthMethod != operatorauth.AuthMethodLocalAPI) || !(a.AuthCapability == "admin" || strings.HasSuffix(a.AuthCapability, "/clawctl-admin") || strings.HasSuffix(a.AuthCapability, "-admin")) {
		return operatorError("FORBIDDEN", "disk operations require a verified human admin session")
	}
	return nil
}
func (s *Store) DiskPolicies() ([]OpsPolicy, error) {
	rows, err := s.rdb.Query(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at FROM ops_policies ORDER BY id,revision DESC LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []OpsPolicy{}
	for rows.Next() {
		p, err := scanOpsPolicy(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func scanOpsPolicy(row interface{ Scan(...any) error }) (OpsPolicy, error) {
	var p OpsPolicy
	var raw, at string
	var superseded sql.NullString
	err := row.Scan(&p.ID, &p.Kind, &p.Revision, &raw, &p.Digest, &p.CreatedBy, &at, &superseded)
	p.Body = json.RawMessage(raw)
	p.CreatedAt = parseTime(at)
	if superseded.Valid {
		t := parseTime(superseded.String)
		p.SupersededAt = &t
	}
	return p, err
}
func (s *Store) DiskPolicy(id string) (OpsPolicy, error) {
	p, err := scanOpsPolicy(s.rdb.QueryRow(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at FROM ops_policies WHERE id=? ORDER BY revision DESC LIMIT 1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		err = operatorError(OperatorCodeMaintenanceNotFound, "disk policy not found")
	}
	return p, err
}

// DiskPolicyUpsert authorizes before replay and atomically supersedes, revokes
// pending approvals, stores a receipt and audits without persisting protect paths
// in the audit log. Updating creates a new immutable body, never overwrites one.
func (s *Store) DiskPolicyUpsert(req DiskPolicyRequest, apply bool, key string, audit AuditEntry) (out DiskPolicyResult, err error) {
	audit.Action = AuditDiskPolicyPreview
	if apply {
		audit.Action = AuditDiskPolicyApply
	}
	audit.Subject = req.ID
	audit.IdempotencyKey = key
	rejectEarly := func(e error) (DiskPolicyResult, error) {
		audit.OK = false
		audit.Detail = "disk policy request rejected"
		if ae := s.RecordAudit(audit); ae != nil {
			return out, ae
		}
		return out, e
	}
	if err = humanDiskAdmin(audit); err != nil {
		return rejectEarly(err)
	}
	if apply {
		if err = s.diskWriteScope(audit); err != nil {
			return rejectEarly(err)
		}
	}
	if !validJobReadStoredIdentifier(req.ID, 128) || req.ExpectedRevision == nil || *req.ExpectedRevision < 0 || strings.TrimSpace(req.Reason) == "" || len(req.Reason) > 500 || scriptcatalog.Redact(req.Reason) != req.Reason {
		return rejectEarly(operatorError("BAD_REQUEST", "id, expected_revision and safe reason required"))
	}
	_, body, bodyDigest, err := CanonicalDiskPolicy(req.Body)
	if err != nil {
		return rejectEarly(err)
	}
	req.Body = body
	now := s.now().UTC().Truncate(time.Second)
	if !apply {
		req.ExpiresAt = now.Add(30 * time.Minute)
	}
	binding := req
	binding.PreviewDigest = ""
	digest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(binding))
	audit.RequestDigest = "sha256:" + scriptcatalog.Digest(mustScriptJSON(struct {
		Actor   string
		Request DiskPolicyRequest
	}{audit.AuthSubject, req}))
	tx, err := s.beginWrite(context.Background(), "disk_policy_upsert")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	reject := func(code, detail string) (DiskPolicyResult, error) {
		audit.OK = false
		audit.Detail = detail
		if e := s.recordAuditTx(tx, audit); e != nil {
			return out, e
		}
		if e := tx.Commit(); e != nil {
			return out, e
		}
		return out, operatorError(code, detail)
	}
	if apply {
		if key == "" || len(key) > 200 {
			return reject("BAD_REQUEST", "idempotency key required")
		}
		var op, rd, response string
		e := tx.QueryRow(`SELECT operation,request_digest,COALESCE(response_json,'') FROM operator_idempotency WHERE idempotency_key=?`, key).Scan(&op, &rd, &response)
		if e == nil {
			if op != "disk-policy-v1" || rd != audit.RequestDigest {
				return reject("REVISION_CONFLICT", "idempotency conflict")
			}
			if e = json.Unmarshal([]byte(response), &out); e != nil {
				return out, e
			}
			out.Replayed = true
			audit.OK = true
			audit.Detail = OperatorIdempotencyReplayPrefix + "disk policy receipt"
			if e = s.recordAuditTx(tx, audit); e != nil {
				return out, e
			}
			return out, tx.Commit()
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return out, e
		}
		if req.PreviewDigest != digest || !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(30*time.Minute)) {
			return reject("PRECONDITION_FAILED", "invalid or expired preview binding")
		}
	}
	var revision int64
	if err = tx.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM ops_policies WHERE id=?`, req.ID).Scan(&revision); err != nil {
		return out, err
	}
	if revision != *req.ExpectedRevision {
		return reject("REVISION_CONFLICT", "policy revision changed")
	}
	var previousBody json.RawMessage
	if revision > 0 {
		var previous string
		if err = tx.QueryRow(`SELECT body FROM ops_policies WHERE id=? AND revision=?`, req.ID, revision).Scan(&previous); err != nil {
			return out, err
		}
		previousBody = json.RawMessage(previous)
	}
	out = DiskPolicyResult{Policy: OpsPolicy{ID: req.ID, Kind: "disk", Revision: revision + 1, Body: body, Digest: bodyDigest, CreatedBy: audit.AuthSubject, CreatedAt: now}, ExpectedRevision: revision, ExpiresAt: req.ExpiresAt, PreviewDigest: digest, PreviousBody: previousBody, Warnings: []string{"Execution requires reviewed disk adapters and deployment-configured canary evidence."}}
	if apply {
		if _, err = tx.Exec(`UPDATE ops_policies SET superseded_at=? WHERE id=? AND superseded_at IS NULL`, fmtTime(now), req.ID); err != nil {
			return out, err
		}

		// Revoke queued work as well as unconsumed grants. Running work requires
		// adapter safe-boundary cancellation and is not implemented by this foundation.
		if _, err = tx.Exec(`UPDATE jobs SET state='rejected',terminal_at=?,lease_token=NULL,lease_expires_at=NULL WHERE job_id IN (SELECT job_id FROM ops_approvals WHERE policy_id=? AND state='consumed') AND state IN ('not_started','claimed')`, fmtTime(now), req.ID); err != nil {
			return out, err
		}
		if _, err = tx.Exec(`UPDATE ops_approvals SET state='rejected',decided_at=?,decision_actor=? WHERE policy_id=? AND state IN ('pending','approved')`, fmtTime(now), audit.AuthSubject, req.ID); err != nil {
			return out, err
		}
		if _, err = tx.Exec(`INSERT INTO ops_policies(id,kind,revision,body,digest,created_by,created_at) VALUES (?,'disk',?,?,?,?,?)`, req.ID, revision+1, string(body), bodyDigest, audit.AuthSubject, fmtTime(now)); err != nil {
			return out, err
		}
		if _, err = tx.Exec(`INSERT INTO operator_idempotency(idempotency_key,operation,request_digest,outcome,response_json,created_at) VALUES (?,'disk-policy-v1',?,'ok',?,?)`, key, audit.RequestDigest, string(mustScriptJSON(out)), fmtTime(now)); err != nil {
			return out, err
		}
	}
	audit.OK = true
	audit.Detail = string(mustScriptJSON(struct {
		PolicyID      string `json:"policy_id"`
		Revision      int64  `json:"revision"`
		PolicyDigest  string `json:"policy_digest"`
		PreviewDigest string `json:"preview_digest"`
	}{req.ID, out.Policy.Revision, bodyDigest, digest}))
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
