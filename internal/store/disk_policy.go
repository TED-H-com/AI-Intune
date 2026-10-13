package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/diskpolicy"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// Disk policy aliases preserve the P2-01 public Go API.
type DiskPolicy = diskpolicy.DiskPolicy
type DiskSafeTier = diskpolicy.DiskSafeTier
type DiskThresholds = diskpolicy.DiskThresholds
type DiskScanBudgets = diskpolicy.DiskScanBudgets
type DiskProtectionRules = diskpolicy.DiskProtectionRules

func DefaultDiskPolicy() DiskPolicy { return diskpolicy.DefaultDiskPolicy() }
func CanonicalDiskPolicy(raw json.RawMessage) (DiskPolicy, json.RawMessage, string, error) {
	p, canonical, digest, err := diskpolicy.CanonicalDiskPolicy(raw)
	if err != nil {
		err = operatorError("BAD_REQUEST", err.Error())
	}
	return p, canonical, digest, err
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
	ID                      string          `json:"id"`
	Body                    json.RawMessage `json:"body"`
	ExpectedRevision        *int64          `json:"expected_revision"`
	ExpiresAt               time.Time       `json:"expires_at,omitempty"`
	PreviewDigest           string          `json:"preview_digest,omitempty"`
	Reason                  string          `json:"reason"`
	AcknowledgeRemovedPaths []string        `json:"acknowledge_removed_paths,omitempty"`
}
type DiskPolicyResult struct {
	Policy              OpsPolicy       `json:"policy"`
	ExpectedRevision    int64           `json:"expected_revision"`
	ExpiresAt           time.Time       `json:"expires_at"`
	PreviewDigest       string          `json:"preview_digest"`
	Replayed            bool            `json:"replayed"`
	Warnings            []string        `json:"warnings"`
	PreviousBody        json.RawMessage `json:"previous_body,omitempty"`
	RemovedProtectPaths []string        `json:"removed_protect_paths,omitempty"`
}

func humanDiskAdmin(a AuditEntry) error {
	if a.AuthSubject == "" || a.AuthDecision != string(operatorauth.Authorized) || (a.AuthMethod != operatorauth.AuthMethodLocalAccountSession && a.AuthMethod != operatorauth.AuthMethodLocalAPI) || !(a.AuthCapability == "admin" || strings.HasSuffix(a.AuthCapability, "/clawctl-admin") || strings.HasSuffix(a.AuthCapability, "-admin")) {
		return operatorError("FORBIDDEN", "disk operations require a verified human admin session")
	}
	return nil
}
func (s *Store) DiskPolicies() ([]OpsPolicy, error) {
	rows, err := s.rdb.Query(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at FROM ops_policies WHERE kind='disk' ORDER BY id,revision DESC LIMIT 500`)
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
	p, err := scanOpsPolicy(s.rdb.QueryRow(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at FROM ops_policies WHERE kind='disk' AND id=? ORDER BY revision DESC LIMIT 1`, id))
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
	policy, body, bodyDigest, err := CanonicalDiskPolicy(req.Body)
	if err != nil {
		return rejectEarly(err)
	}
	req.Body = body
	now := s.now().UTC().Truncate(time.Second)
	if !apply {
		req.ExpiresAt = now.Add(30 * time.Minute)
	}
	req.AcknowledgeRemovedPaths = append([]string(nil), req.AcknowledgeRemovedPaths...)
	sort.Strings(req.AcknowledgeRemovedPaths)
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
		applyBinding := req
		applyBinding.PreviewDigest = ""
		if req.PreviewDigest != "sha256:"+scriptcatalog.Digest(mustScriptJSON(applyBinding)) || !req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(30*time.Minute)) {
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
	if revision > 0 {
		var kind string
		if err = tx.QueryRow(`SELECT kind FROM ops_policies WHERE id=? AND revision=?`, req.ID, revision).Scan(&kind); err != nil {
			return out, err
		}
		if kind != "disk" {
			return reject("REVISION_CONFLICT", "policy kind does not match disk operation")
		}
	}
	var previousBody json.RawMessage
	if revision > 0 {
		var previous string
		if err = tx.QueryRow(`SELECT body FROM ops_policies WHERE id=? AND revision=?`, req.ID, revision).Scan(&previous); err != nil {
			return out, err
		}
		previousBody = json.RawMessage(previous)
	}
	var previousPolicy DiskPolicy
	if len(previousBody) > 0 {
		if err = json.Unmarshal(previousBody, &previousPolicy); err != nil {
			return out, err
		}
	}
	removed := []string{}
	nextPaths := map[string]bool{}
	for _, v := range policy.ProtectPaths {
		nextPaths[v] = true
	}
	for _, v := range previousPolicy.ProtectPaths {
		if !nextPaths[v] {
			removed = append(removed, v)
		}
	}
	sort.Strings(removed)
	if apply && len(removed) > 0 && !reflect.DeepEqual(req.AcknowledgeRemovedPaths, removed) {
		return reject("PRECONDITION_FAILED", "explicit acknowledgement of every removed protection required")
	}
	if len(removed) == 0 && len(req.AcknowledgeRemovedPaths) > 0 {
		return reject("BAD_REQUEST", "unexpected removal acknowledgement")
	}
	// Preview lists the exact acknowledgement set. Apply must supply the same set;
	// both the preview digest and the transaction's current revision bind it.
	binding := req
	binding.PreviewDigest = ""
	binding.AcknowledgeRemovedPaths = nil
	if len(removed) > 0 {
		binding.AcknowledgeRemovedPaths = removed
	}
	digest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(binding))
	if apply && req.PreviewDigest != digest {
		return reject("PRECONDITION_FAILED", "invalid preview binding")
	}
	out = DiskPolicyResult{Policy: OpsPolicy{ID: req.ID, Kind: "disk", Revision: revision + 1, Body: body, Digest: bodyDigest, CreatedBy: audit.AuthSubject, CreatedAt: now}, ExpectedRevision: revision, ExpiresAt: req.ExpiresAt, PreviewDigest: digest, PreviousBody: previousBody, RemovedProtectPaths: removed, Warnings: []string{"Execution requires reviewed disk adapters and deployment-configured canary evidence."}}
	if apply {
		if _, err = tx.Exec(`UPDATE ops_policies SET superseded_at=? WHERE id=? AND superseded_at IS NULL`, fmtTime(now), req.ID); err != nil {
			return out, err
		}

		// Revoke queued work as well as unconsumed grants. Running work requires
		// adapter safe-boundary cancellation and is not implemented by this foundation.
		if _, err = tx.Exec(`UPDATE jobs SET state='rejected',terminal_at=?,lease_token=NULL,lease_expires_at=NULL WHERE job_id IN (SELECT job_id FROM ops_approvals WHERE policy_id=? AND state='consumed') AND state IN ('not_started','claimed')`, fmtTime(now), req.ID); err != nil {
			return out, err
		}
		// Safe-tier catalog jobs bind policy identity in closed args rather than
		// a deep-item approval. Revoke their queued/claimed dispatch in this transaction.
		if _, err = tx.Exec(`UPDATE jobs SET state='rejected',terminal_at=?,lease_token=NULL,lease_expires_at=NULL WHERE state IN ('not_started','claimed') AND desired_id IN (SELECT desired_id FROM desired_state WHERE resource_kind='script_v1' AND resource_id IN ('disk-safe-preview-v2','disk-safe-clean-v2') AND CASE WHEN json_valid(spec) THEN json_extract(spec,'$.args.policy_id') ELSE NULL END=?)`, fmtTime(now), req.ID); err != nil {
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
		PolicyID           string `json:"policy_id"`
		Revision           int64  `json:"revision"`
		PolicyDigest       string `json:"policy_digest"`
		PreviewDigest      string `json:"preview_digest"`
		RemovedPathCount   int    `json:"removed_path_count"`
		RemovedPathsDigest string `json:"removed_paths_digest"`
	}{req.ID, out.Policy.Revision, bodyDigest, digest, len(removed), "sha256:" + scriptcatalog.Digest(mustScriptJSON(removed))}))
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
