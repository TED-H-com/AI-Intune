package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

const QuarantineTTL = 7 * 24 * time.Hour

// DiskActionRequest selects evidence IDs, never caller-authored paths or identities.
type DiskActionRequest struct {
	ReportID     string   `json:"report_id"`
	ReportDigest string   `json:"report_digest"`
	Action       string   `json:"action"`
	ItemIDs      []string `json:"item_ids"`
	Reason       string   `json:"reason"`
}

type DiskManifest struct {
	Schema               string            `json:"schema"`
	ID                   string            `json:"id"`
	ApprovalID           string            `json:"approval_id"`
	MachineID            string            `json:"machine_id"`
	ReportID             string            `json:"report_id"`
	ReportDigest         string            `json:"report_digest"`
	Action               string            `json:"action"`
	Initiator            string            `json:"initiator"`
	Reason               string            `json:"reason"`
	PolicyID             string            `json:"policy_id"`
	PolicyRevision       int64             `json:"policy_revision"`
	PolicyDigest         string            `json:"policy_digest"`
	CreatedAt            time.Time         `json:"created_at"`
	Deadline             time.Time         `json:"deadline"`
	QuarantineManifestID string            `json:"quarantine_manifest_id,omitempty"`
	TTLSeconds           int64             `json:"ttl_seconds"`
	Items                []diskreport.Item `json:"items"`
}

// DiskActionPreview deliberately cannot serialize the private manifest body.
type DiskActionPreview struct {
	ManifestID           string            `json:"manifest_id"`
	Digest               string            `json:"manifest_digest"`
	Approval             OpsApproval       `json:"approval"`
	Items                []diskreport.Item `json:"items"`
	AllocatedBytes       int64             `json:"allocated_bytes"`
	LogicalBytes         int64             `json:"logical_bytes"`
	QuarantineManifestID string            `json:"quarantine_manifest_id,omitempty"`
	TTLSeconds           int64             `json:"ttl_seconds"`
}

func manifestID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "manifest-" + hex.EncodeToString(b[:]), nil
}

// DiskActionPreview snapshots exact report bindings and creates the pending
// human decision atomically. Previewing does not authorize any machine mutation.
func (s *Store) DiskActionPreview(req DiskActionRequest, audit AuditEntry) (out DiskActionPreview, err error) {
	defer func() {
		if err != nil {
			audit.Action = AuditOpsApproval
			audit.Subject = "disk action preview"
			audit.OK = false
			audit.Detail = "manifest preview rejected"
			if ae := s.RecordAudit(audit); ae != nil {
				err = ae
			}
		}
	}()
	if err = humanDiskAdmin(audit); err != nil {
		return out, err
	}
	if req.Action != "quarantine" && req.Action != "delete" && req.Action != "reject" || len(req.ItemIDs) < 1 || len(req.ItemIDs) > 100 || !validJobReadStoredIdentifier(req.ReportID, 128) || !validLowerSHA256Digest(req.ReportDigest) || strings.TrimSpace(req.Reason) != req.Reason || req.Reason == "" || len(req.Reason) > 500 || scriptcatalog.Redact(req.Reason) != req.Reason || strings.ContainsAny(req.Reason, "\r\n\x00") {
		return out, operatorError("BAD_REQUEST", "bounded selection, action, report digest and safe reason required")
	}
	ids := append([]string(nil), req.ItemIDs...)
	sort.Strings(ids)
	for n, id := range ids {
		if !validJobReadStoredIdentifier(id, 128) || n > 0 && ids[n-1] == id {
			return out, operatorError("BAD_REQUEST", "invalid or duplicate item ID")
		}
	}
	tx, err := s.beginWrite(context.Background(), "disk_action_preview")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	now := s.now().UTC().Truncate(time.Second)
	var machine, digest, meta string
	err = tx.QueryRow(`SELECT machine_id,digest,metadata FROM disk_reports WHERE id=? AND completed_at IS NOT NULL AND created_at>=?`, req.ReportID, fmtTime(now.Add(-6*time.Hour))).Scan(&machine, &digest, &meta)
	if err == sql.ErrNoRows {
		return out, operatorError("PRECONDITION_FAILED", "report missing or stale")
	}
	if err != nil {
		return out, err
	}
	if digest != req.ReportDigest {
		return out, operatorError("REVISION_CONFLICT", "report digest changed")
	}
	var report diskreport.Report
	if err = json.Unmarshal([]byte(meta), &report); err != nil {
		return out, err
	}
	var revision int64
	if err = tx.QueryRow(`SELECT revision FROM ops_policies WHERE id=? AND digest=? AND superseded_at IS NULL`, report.PolicyID, report.PolicyDigest).Scan(&revision); err == sql.ErrNoRows {
		return out, operatorError("REVISION_CONFLICT", "report policy revoked")
	}
	if err != nil {
		return out, err
	}
	id, err := manifestID()
	if err != nil {
		return out, err
	}
	m := DiskManifest{Schema: "disk-action/v1", ID: id, ApprovalID: "approval-" + strings.TrimPrefix(id, "manifest-"), MachineID: machine, ReportID: req.ReportID, ReportDigest: digest, Action: req.Action, Initiator: audit.AuthSubject, Reason: req.Reason, PolicyID: report.PolicyID, PolicyRevision: revision, PolicyDigest: report.PolicyDigest, CreatedAt: now, Deadline: now.Add(30 * time.Minute), TTLSeconds: int64(QuarantineTTL / time.Second), Items: []diskreport.Item{}}
	out.Items = []diskreport.Item{}
	for _, selected := range ids {
		var body, path string
		err = tx.QueryRow(`SELECT body,private_path FROM disk_report_items WHERE report_id=? AND item_id=?`, req.ReportID, selected).Scan(&body, &path)
		if err == sql.ErrNoRows {
			return out, operatorError("BAD_REQUEST", "selected item not in report")
		}
		if err != nil {
			return out, err
		}
		var item diskreport.Item
		if err = json.Unmarshal([]byte(body), &item); err != nil {
			return out, err
		}
		// Phase 2 file adapter cannot authorize Docker/process/directory identities.
		if req.Action != "reject" && (!filepath.IsAbs(path) || filepath.Clean(path) != path || item.ExclusionReason != "" || item.Identity.Type != 0100000 || item.Identity.Inode == 0 || item.Identity.Dev == 0 || item.OwnerUID < 0 || item.Identity.Size < 0 || item.LogicalBytes != item.Identity.Size || item.Category == "unused-docker-images" || item.Category == "orphaned-processes" || item.Identity.MtimeNS <= 0 || item.Identity.CtimeNS <= 0 || item.PID != 0 || item.HolderCount != 0) {
			return out, operatorError("PRECONDITION_FAILED", "selected item lacks eligible exact regular-file evidence")
		}
		item.PrivatePath = path
		m.Items = append(m.Items, item)
		out.Items = append(out.Items, diskreport.PublicItem(item))
		// Both values are bounded by the report contract; guard accumulated overflow.
		if item.AllocatedBytes < 0 || item.LogicalBytes < 0 || out.AllocatedBytes > int64(^uint64(0)>>1)-item.AllocatedBytes || out.LogicalBytes > int64(^uint64(0)>>1)-item.LogicalBytes {
			return out, operatorError("BAD_REQUEST", "item bytes overflow")
		}
		out.AllocatedBytes += item.AllocatedBytes
		out.LogicalBytes += item.LogicalBytes
	}
	raw := mustScriptJSON(m)
	out.ManifestID = id
	out.Digest = diskreport.Digest(raw)
	out.TTLSeconds = m.TTLSeconds
	a := OpsApproval{ID: m.ApprovalID, State: "pending", Actor: m.Initiator, MachineID: machine, Operation: m.Action, PolicyID: m.PolicyID, PolicyRevision: revision, PolicyDigest: m.PolicyDigest, ItemDigest: out.Digest, CreatedAt: now, Deadline: m.Deadline}
	out.Approval = a
	if _, err = tx.Exec(`INSERT INTO ops_approvals(id,state,actor,machine_id,operation,policy_id,policy_revision,policy_digest,item_digest,created_at,deadline) VALUES (?,'pending',?,?,?,?,?,?,?,?,?)`, a.ID, a.Actor, a.MachineID, a.Operation, a.PolicyID, a.PolicyRevision, a.PolicyDigest, a.ItemDigest, fmtTime(now), fmtTime(a.Deadline)); err != nil {
		return out, err
	}
	if _, err = tx.Exec(`INSERT INTO ops_manifests VALUES (?,?,?,?,?,?,?)`, id, a.ID, machine, out.Digest, string(raw), fmtTime(now), fmtTime(m.Deadline)); err != nil {
		return out, err
	}
	audit.Action = AuditOpsApproval
	audit.Subject = a.ID
	audit.MachineID = machine
	audit.OK = true
	audit.Detail = "manifest preview " + opsApprovalAuditDetail(a)
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

// DiskManifestForJob returns private bytes only for a live, exactly bound job.
// A manifest ID, digest, operator session or unassigned machine grants nothing.
func (s *Store) DiskManifestForJob(machine, job, id, digest string) (json.RawMessage, error) {
	tx, err := s.beginWrite(context.Background(), "disk_manifest_fetch")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	raw, _, err := diskManifestForJobTx(tx, machine, job, id, digest, s.now().UTC())
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	return raw, nil
}

func diskManifestForJobTx(tx dbTx, machine, job, id, digest string, now time.Time) (json.RawMessage, time.Time, error) {
	var body, stored, expiry, spec, state, lease string
	err := tx.QueryRow(`SELECT m.body,m.digest,m.expires_at,d.spec,j.state,COALESCE(j.lease_expires_at,'') FROM ops_manifests m JOIN ops_approvals a ON a.id=m.approval_id JOIN jobs j ON j.job_id=a.job_id JOIN desired_state d ON d.desired_id=j.desired_id WHERE m.id=? AND m.machine_id=? AND j.machine_id=? AND j.job_id=? AND a.state='consumed'`, id, machine, machine, job).Scan(&body, &stored, &expiry, &spec, &state, &lease)
	if err == sql.ErrNoRows {
		return nil, time.Time{}, operatorError("FORBIDDEN", "manifest job not assigned")
	}
	if err != nil {
		return nil, time.Time{}, err
	}
	if state != "running" || !parseTime(lease).After(now) || !parseTime(expiry).After(now) || digest != stored || diskreport.Digest([]byte(body)) != stored {
		return nil, time.Time{}, operatorError("PRECONDITION_FAILED", "manifest job inactive, expired or digest mismatch")
	}
	v, err := scriptcatalog.Decode([]byte(spec))
	if err != nil {
		return nil, time.Time{}, operatorError("PRECONDITION_FAILED", "invalid manifest job")
	}
	entry, ok := scriptcatalog.Lookup(v.ScriptID)
	if !ok || entry.Mode != "write" || v.ScriptSHA256 != entry.SHA256 || scriptcatalog.Digest(entry.Bytes) != entry.SHA256 {
		return nil, time.Time{}, operatorError("PRECONDITION_FAILED", "unreviewed manifest script")
	}
	var args struct {
		ID       string `json:"manifest_id"`
		Digest   string `json:"manifest_digest"`
		Approval string `json:"approval_id"`
	}
	var m DiskManifest
	if json.Unmarshal(v.Args, &args) != nil || json.Unmarshal([]byte(body), &m) != nil || args.ID != id || args.Digest != digest || args.Approval != m.ApprovalID || v.ExecutionMode != "write" || v.ScriptID != scriptcatalog.DiskActionScript(m.Action) {
		return nil, time.Time{}, operatorError("PRECONDITION_FAILED", "manifest job binding mismatch")
	}
	var current int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, m.PolicyID, m.PolicyRevision, m.PolicyDigest).Scan(&current); err != nil {
		return nil, time.Time{}, err
	}
	if current != 1 {
		return nil, time.Time{}, operatorError("PRECONDITION_FAILED", "manifest policy revoked")
	}
	deadline := parseTime(lease)
	if parseTime(expiry).Before(deadline) {
		deadline = parseTime(expiry)
	}
	return json.RawMessage(body), deadline, nil
}
