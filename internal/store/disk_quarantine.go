package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

type DiskQuarantineItem struct {
	ManifestID       string    `json:"manifest_id"`
	ItemID           string    `json:"item_id"`
	MachineID        string    `json:"machine_id"`
	DisplayPath      string    `json:"display_path"`
	State            string    `json:"state"`
	AllocatedBytes   int64     `json:"allocated_bytes"`
	QuarantinedAt    time.Time `json:"quarantined_at"`
	ExpiresAt        time.Time `json:"expires_at"`
	RemainingSeconds int64     `json:"remaining_seconds"`
}
type DiskActionRecord struct {
	State          string              `json:"state"`
	Identity       diskreport.Identity `json:"identity"`
	OriginalParent []uint64            `json:"original_parent"`
	OwnerUID       int64               `json:"owner_uid"`
	QuarantinedAt  float64             `json:"quarantined_at"`
	ExpiresAt      float64             `json:"expires_at"`
}
type DiskActionItemResult struct {
	ManifestID string            `json:"manifest_id"`
	ItemID     string            `json:"item_id"`
	Status     string            `json:"status"`
	Reason     string            `json:"reason"`
	Record     *DiskActionRecord `json:"record,omitempty"`
}
type DiskActionResults struct {
	Schema           string                 `json:"schema"`
	JobID            string                 `json:"job_id"`
	Items            []DiskActionItemResult `json:"items"`
	QuarantinedBytes int64                  `json:"quarantined_bytes"`
	FreedBytes       int64                  `json:"freed_bytes"`
	OmittedItems     int                    `json:"omitted_items,omitempty"`
}

func (s *Store) DiskQuarantineList(machine string) ([]DiskQuarantineItem, error) {
	rows, err := s.rdb.Query(`SELECT q.manifest_id,q.item_id,q.machine_id,q.state,q.allocated_bytes,q.quarantined_at,q.expires_at,m.body FROM disk_quarantine q JOIN ops_manifests m ON m.id=q.manifest_id WHERE q.machine_id=? AND q.state IN ('quarantined','restore_pending') ORDER BY q.expires_at,q.manifest_id,q.item_id LIMIT 500`, machine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiskQuarantineItem{}
	for rows.Next() {
		var item DiskQuarantineItem
		var at, expires, body string
		if err = rows.Scan(&item.ManifestID, &item.ItemID, &item.MachineID, &item.State, &item.AllocatedBytes, &at, &expires, &body); err != nil {
			return nil, err
		}
		var m DiskManifest
		if err = json.Unmarshal([]byte(body), &m); err != nil {
			return nil, err
		}
		for _, i := range m.Items {
			if i.ID == item.ItemID {
				item.DisplayPath = diskreport.PublicItem(i).DisplayPath
			}
		}
		item.QuarantinedAt = parseTime(at)
		item.ExpiresAt = parseTime(expires)
		item.RemainingSeconds = int64(item.ExpiresAt.Sub(s.now().UTC()).Seconds())
		if item.RemainingSeconds < 0 {
			item.RemainingSeconds = 0
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// Results are authenticated observations, not new execution grants. Late durable
// journal recovery is accepted for the original assigned consumed job, including
// after revocation; terminal quarantine rows can never be resurrected.
func (s *Store) DiskActionResults(machine, job string, result DiskActionResults) (string, error) {
	if result.Schema != "disk-action-result/v1" || result.JobID != job || len(result.Items) > 100 || result.OmittedItems != 0 {
		return "", operatorError("BAD_REQUEST", "invalid bounded action results")
	}
	tx, err := s.beginWrite(context.Background(), "disk_action_results")
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	manifests, action, err := diskJobManifestsTx(tx, machine, job)
	if err != nil {
		return "", err
	}
	digest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(result))
	var prior string
	err = tx.QueryRow(`SELECT digest FROM disk_action_receipts WHERE job_id=? AND machine_id=?`, job, machine).Scan(&prior)
	if err == nil {
		if prior != digest {
			return "", operatorError("REVISION_CONFLICT", "result replay differs")
		}
		return digest, tx.Commit()
	}
	if err != sql.ErrNoRows {
		return "", err
	}
	now := s.now().UTC()
	seen := map[string]bool{}
	for _, row := range result.Items {
		m, ok := manifests[row.ManifestID]
		if !ok {
			return "", operatorError("FORBIDDEN", "result manifest not assigned")
		}
		key := row.ManifestID + "/" + row.ItemID
		if seen[key] {
			return "", operatorError("BAD_REQUEST", "duplicate result")
		}
		seen[key] = true
		var item diskreport.Item
		found := false
		for _, i := range m.Items {
			if i.ID == row.ItemID {
				item = i
				found = true
			}
		}
		if !found || len(row.Reason) > 128 || scriptcatalog.Redact(row.Reason) != row.Reason {
			return "", operatorError("BAD_REQUEST", "invalid result item or reason")
		}
		valid := row.Status == "skipped"
		switch action {
		case "quarantine":
			valid = valid || row.Status == "quarantined" || row.Status == "already_quarantined" || row.Status == "recovered_quarantine"
		case "delete":
			valid = valid || row.Status == "deleted" || row.Status == "recovered_quarantine" || row.Status == "already_quarantined"
		case "restore":
			valid = valid || row.Status == "restored" || row.Status == "already_restored" || row.Status == "recovered_restore"
		case "expire":
			valid = valid || row.Status == "expired" || row.Status == "already_expired"
		}
		if !valid {
			return "", operatorError("BAD_REQUEST", "invalid action outcome")
		}
		if row.Status != "skipped" && row.Record == nil {
			return "", operatorError("BAD_REQUEST", "successful outcome requires a journal record")
		}
		if row.Record != nil {
			r := row.Record
			stable := r.Identity.Dev == item.Identity.Dev && r.Identity.Inode == item.Identity.Inode && r.Identity.Type == item.Identity.Type && r.Identity.Size == item.Identity.Size && r.Identity.MtimeNS == item.Identity.MtimeNS
			minimum := m.CreatedAt
			if m.Action == "restore" {
				var originalBody string
				if err = tx.QueryRow(`SELECT body FROM ops_manifests WHERE id=?`, m.QuarantineManifestID).Scan(&originalBody); err != nil {
					return "", err
				}
				var original DiskManifest
				if json.Unmarshal([]byte(originalBody), &original) != nil {
					return "", operatorError("PRECONDITION_FAILED", "original manifest invalid")
				}
				minimum = original.CreatedAt
			}
			at := time.Unix(0, int64(r.QuarantinedAt*1e9)).UTC()
			expires := time.Unix(0, int64(r.ExpiresAt*1e9)).UTC()
			if !stable || r.Identity.CtimeNS <= 0 || r.OwnerUID != item.OwnerUID || len(r.OriginalParent) != 2 || r.OriginalParent[0] == 0 || r.OriginalParent[1] == 0 || at.Before(minimum.Add(-5*time.Minute)) || at.After(now.Add(5*time.Minute)) || expires.Before(at.Add(QuarantineTTL)) || expires.After(at.Add(QuarantineTTL+time.Minute)) {
				return "", operatorError("BAD_REQUEST", "quarantine record identity or TTL mismatch")
			}
			original := m.ID
			if m.Action == "restore" {
				original = m.QuarantineManifestID
			}
			if r.State != "quarantined" && r.State != "restore_pending" && r.State != "restored" && r.State != "expired" && r.State != "deleted" {
				return "", operatorError("BAD_REQUEST", "invalid quarantine state")
			}
			if action == "expire" && r.State != "quarantined" && r.State != "expired" || action == "quarantine" && r.State != "quarantined" {
				return "", operatorError("BAD_REQUEST", "state does not match action")
			}
			if action == "restore" && r.State != "restored" && r.State != "restore_pending" && r.State != "quarantined" {
				return "", operatorError("BAD_REQUEST", "invalid restore state")
			}
			if _, err = tx.Exec(`INSERT INTO disk_quarantine VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(manifest_id,item_id) DO UPDATE SET state=excluded.state,identity=excluded.identity,received_at=excluded.received_at WHERE disk_quarantine.state IN ('quarantined','restore_pending')`, original, item.ID, machine, r.State, string(mustScriptJSON(r.Identity)), string(mustScriptJSON(r.OriginalParent)), fmtTime(at), fmtTime(expires), fmtTime(now), item.AllocatedBytes); err != nil {
				return "", err
			}
		}
		if _, err = tx.Exec(`INSERT INTO disk_action_items VALUES (?,?,?,?,?,?,?)`, job, row.ManifestID, row.ItemID, machine, row.Status, row.Reason, fmtTime(now)); err != nil {
			return "", err
		}
	}
	if _, err = tx.Exec(`INSERT INTO disk_action_receipts VALUES (?,?,?,?)`, job, machine, digest, fmtTime(now)); err != nil {
		return "", err
	}
	if err = s.recordAuditTx(tx, AuditEntry{At: now, Action: AuditOpsApproval, Subject: job, MachineID: machine, OK: true, Detail: "disk action results digest=" + digest}); err != nil {
		return "", err
	}
	return digest, tx.Commit()
}

func diskJobManifestsTx(tx dbTx, machine, job string) (map[string]DiskManifest, string, error) {
	var raw string
	if err := tx.QueryRow(`SELECT d.spec FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.job_id=? AND j.machine_id=? AND d.resource_kind='script_v1'`, job, machine).Scan(&raw); err != nil {
		return nil, "", operatorError("FORBIDDEN", "action job not assigned")
	}
	spec, err := scriptcatalog.Decode([]byte(raw))
	e, ok := scriptcatalog.Lookup(spec.ScriptID)
	if err != nil || !ok || !scriptcatalog.IsDiskAction(e.ID) || !validLowerSHA256(spec.ScriptSHA256) || spec.ExecutionMode != "write" {
		return nil, "", operatorError("PRECONDITION_FAILED", "unreviewed action job")
	}
	out := map[string]DiskManifest{}
	if e.ID == "disk-quarantine-expire-v1" {
		var selectionRaw string
		if err = tx.QueryRow(`SELECT selection FROM disk_expiry_jobs WHERE job_id=? AND machine_id=?`, job, machine).Scan(&selectionRaw); err != nil {
			return nil, "", operatorError("FORBIDDEN", "expiry job not authorized")
		}
		var selection map[string][]string
		if err = json.Unmarshal([]byte(selectionRaw), &selection); err != nil {
			return nil, "", err
		}
		for id, ids := range selection {
			var body string
			if err = tx.QueryRow(`SELECT m.body FROM ops_manifests m JOIN ops_approvals a ON a.id=m.approval_id WHERE m.id=? AND m.machine_id=? AND a.state='consumed' AND a.operation='quarantine'`, id, machine).Scan(&body); err != nil {
				return nil, "", err
			}
			var m DiskManifest
			if err = json.Unmarshal([]byte(body), &m); err != nil {
				return nil, "", err
			}
			items := []diskreport.Item{}
			for _, i := range m.Items {
				for _, id := range ids {
					if i.ID == id {
						items = append(items, i)
					}
				}
			}
			m.Items = items
			out[m.ID] = m
		}
		return out, "expire", nil
	}
	var args struct {
		ID       string `json:"manifest_id"`
		Digest   string `json:"manifest_digest"`
		Approval string `json:"approval_id"`
	}
	_ = json.Unmarshal(spec.Args, &args)
	var body string
	if err = tx.QueryRow(`SELECT m.body FROM ops_manifests m JOIN ops_approvals a ON a.id=m.approval_id WHERE m.id=? AND m.digest=? AND m.approval_id=? AND a.job_id=? AND a.machine_id=? AND a.state='consumed'`, args.ID, args.Digest, args.Approval, job, machine).Scan(&body); err != nil {
		return nil, "", operatorError("FORBIDDEN", "consumed manifest job required")
	}
	var m DiskManifest
	if err = json.Unmarshal([]byte(body), &m); err != nil {
		return nil, "", err
	}
	out[m.ID] = m
	return out, m.Action, nil
}

type DiskRestoreRequest struct {
	QuarantineID string   `json:"quarantine_id"`
	MachineID    string   `json:"machine_id,omitempty"`
	ItemIDs      []string `json:"item_ids"`
	Reason       string   `json:"reason"`
}

func (s *Store) DiskRestorePreview(req DiskRestoreRequest, audit AuditEntry) (out DiskActionPreview, err error) {
	if err = humanDiskAdmin(audit); err != nil {
		return out, err
	}
	if len(req.ItemIDs) < 1 || len(req.ItemIDs) > 100 || req.Reason == "" || len(req.Reason) > 500 || scriptcatalog.Redact(req.Reason) != req.Reason {
		return out, operatorError("BAD_REQUEST", "bounded selection and safe reason required")
	}
	tx, err := s.beginWrite(context.Background(), "disk_restore_preview")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var body, digest string
	if err = tx.QueryRow(`SELECT body,digest FROM ops_manifests WHERE id=?`, req.QuarantineID).Scan(&body, &digest); err != nil {
		return out, operatorError("NOT_FOUND", "quarantine not found")
	}
	var original DiskManifest
	if err = json.Unmarshal([]byte(body), &original); err != nil {
		return out, err
	}
	if original.Action != "quarantine" || req.MachineID != "" && original.MachineID != req.MachineID {
		return out, operatorError("BAD_REQUEST", "quarantine machine binding mismatch")
	}
	var revision int64
	var policyDigest string
	if err = tx.QueryRow(`SELECT revision,digest FROM ops_policies WHERE id=? AND superseded_at IS NULL`, original.PolicyID).Scan(&revision, &policyDigest); err != nil {
		return out, operatorError("PRECONDITION_FAILED", "restore policy unavailable")
	}
	id, err := manifestID()
	if err != nil {
		return out, err
	}
	now := s.now().UTC().Truncate(time.Second)
	m := original
	m.ID = id
	m.ApprovalID = "approval-" + id
	m.Action = "restore"
	m.Initiator = audit.AuthSubject
	m.Reason = req.Reason
	m.QuarantineManifestID = original.ID
	m.CreatedAt = now
	m.Deadline = now.Add(30 * time.Minute)
	m.PolicyRevision = revision
	m.PolicyDigest = policyDigest
	m.Items = nil
	ids := append([]string(nil), req.ItemIDs...)
	sort.Strings(ids)
	for n, id := range ids {
		if n > 0 && ids[n-1] == id {
			return out, operatorError("BAD_REQUEST", "duplicate restore item")
		}
		var identity, parent string
		if err = tx.QueryRow(`SELECT identity,original_parent FROM disk_quarantine WHERE manifest_id=? AND item_id=? AND state IN ('quarantined','restore_pending')`, original.ID, id).Scan(&identity, &parent); err != nil {
			return out, operatorError("PRECONDITION_FAILED", "quarantine item no longer available")
		}
		found := false
		for _, item := range original.Items {
			if item.ID == id {
				if json.Unmarshal([]byte(identity), &item.Identity) != nil || json.Unmarshal([]byte(parent), &item.OriginalParent) != nil {
					return out, operatorError("PRECONDITION_FAILED", "quarantine identity invalid")
				}
				m.Items = append(m.Items, item)
				out.Items = append(out.Items, diskreport.PublicItem(item))
				out.AllocatedBytes += item.AllocatedBytes
				out.LogicalBytes += item.LogicalBytes
				found = true
			}
		}
		if !found {
			return out, operatorError("BAD_REQUEST", "restore item not in original manifest")
		}
	}
	raw := mustScriptJSON(m)
	out.ManifestID = m.ID
	out.Digest = "sha256:" + scriptcatalog.Digest(raw)
	out.TTLSeconds = int64(QuarantineTTL / time.Second)
	a := OpsApproval{ID: m.ApprovalID, State: "pending", Actor: m.Initiator, MachineID: m.MachineID, Operation: m.Action, PolicyID: m.PolicyID, PolicyRevision: revision, PolicyDigest: policyDigest, ItemDigest: out.Digest, CreatedAt: now, Deadline: m.Deadline}
	out.Approval = a
	if _, err = tx.Exec(`INSERT INTO ops_approvals(id,state,actor,machine_id,operation,policy_id,policy_revision,policy_digest,item_digest,created_at,deadline) VALUES (?,'pending',?,?,?,?,?,?,?,?,?)`, a.ID, a.Actor, a.MachineID, a.Operation, a.PolicyID, a.PolicyRevision, a.PolicyDigest, a.ItemDigest, fmtTime(now), fmtTime(a.Deadline)); err != nil {
		return out, err
	}
	if _, err = tx.Exec(`INSERT INTO ops_manifests VALUES (?,?,?,?,?,?,?)`, m.ID, a.ID, m.MachineID, out.Digest, string(raw), fmtTime(now), fmtTime(m.Deadline)); err != nil {
		return out, err
	}
	audit.Action = AuditOpsApproval
	audit.Subject = a.ID
	audit.MachineID = a.MachineID
	audit.OK = true
	audit.Detail = "restore preview " + opsApprovalAuditDetail(a)
	if err = s.recordAuditTx(tx, audit); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func (s *Store) DiskManifestHuman(id string, audit AuditEntry) (DiskManifest, error) {
	if err := humanDiskAdmin(audit); err != nil {
		return DiskManifest{}, err
	}
	var body string
	if err := s.rdb.QueryRow(`SELECT body FROM ops_manifests WHERE id=?`, id).Scan(&body); err != nil {
		return DiskManifest{}, operatorError("NOT_FOUND", "manifest not found")
	}
	var m DiskManifest
	err := json.Unmarshal([]byte(body), &m)
	for n := range m.Items {
		m.Items[n].PrivatePath = diskreport.ScrubDisplay(m.Items[n].PrivatePath)
	}
	return m, err
}
