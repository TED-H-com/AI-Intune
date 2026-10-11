package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"sort"
	"strconv"
	"time"
)

type DiskReportSummary struct {
	ID        string            `json:"id"`
	JobID     string            `json:"job_id"`
	MachineID string            `json:"machine_id"`
	CreatedAt string            `json:"created_at"`
	Digest    string            `json:"digest"`
	ItemCount int               `json:"item_count"`
	Report    diskreport.Report `json:"report"`
}
type DiskReportPage struct {
	DiskReportSummary
	Items      []diskreport.Item `json:"items"`
	NextCursor string            `json:"next_cursor,omitempty"`
}

func reportJob(tx dbTx, machine, job string, now time.Time) (scriptcatalog.Spec, error) {
	var spec, state, expiry string
	err := tx.QueryRow(`SELECT d.spec,j.state,COALESCE(j.lease_expires_at,'') FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.job_id=? AND j.machine_id=? AND d.resource_id='disk-deep-report-v1' AND d.resource_kind='script_v1'`, job, machine).Scan(&spec, &state, &expiry)
	if err == sql.ErrNoRows {
		return scriptcatalog.Spec{}, operatorError("FORBIDDEN", "report job not assigned")
	}
	if err != nil {
		return scriptcatalog.Spec{}, err
	}
	expires, e := time.Parse(time.RFC3339Nano, expiry)
	if state != "running" || e != nil || !expires.After(now) {
		return scriptcatalog.Spec{}, operatorError("PRECONDITION_FAILED", "report job is not active")
	}
	s, e := scriptcatalog.Decode([]byte(spec))
	entry, _ := scriptcatalog.Lookup("disk-deep-report-v1")
	if e != nil || s.ExecutionMode != "read" || s.ScriptID != entry.ID || s.ScriptSHA256 != entry.SHA256 {
		return s, operatorError("PRECONDITION_FAILED", "invalid report job")
	}
	return s, nil
}
func (s *Store) DiskReportChunk(machine, job string, chunk diskreport.Chunk) (diskreport.Receipt, error) {
	out := diskreport.Receipt{ID: "report-" + job}
	if len(chunk.Data) == 0 || len(chunk.Data) > diskreport.MaxChunk || chunk.Sequence < 0 || chunk.Sequence >= 512 || chunk.Digest != diskreport.Digest(chunk.Data) {
		return out, operatorError("BAD_REQUEST", "invalid chunk bounds or digest")
	}
	tx, err := s.beginWrite(context.Background(), "disk_report_chunk")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if _, err = reportJob(tx, machine, job, s.now().UTC()); err != nil {
		return out, err
	}
	_, err = tx.Exec(`INSERT OR IGNORE INTO disk_reports(id,job_id,machine_id,created_at) VALUES (?,?,?,?)`, out.ID, job, machine, fmtTime(s.now().UTC()))
	if err != nil {
		return out, err
	}
	var sequence, total int
	var completed sql.NullString
	if err = tx.QueryRow(`SELECT next_sequence,total_bytes,completed_at FROM disk_reports WHERE id=?`, out.ID).Scan(&sequence, &total, &completed); err != nil {
		return out, err
	}
	if chunk.Sequence < sequence {
		var digest string
		err = tx.QueryRow(`SELECT digest FROM disk_report_chunks WHERE report_id=? AND sequence=?`, out.ID, chunk.Sequence).Scan(&digest)
		if err == nil && digest == chunk.Digest {
			return out, tx.Commit()
		}
		return out, operatorError("REVISION_CONFLICT", "chunk replay differs")
	}
	if completed.Valid || chunk.Sequence != sequence || total+len(chunk.Data) > diskreport.MaxBytes {
		return out, operatorError("BAD_REQUEST", "chunk sequence or total limit")
	}
	if _, err = tx.Exec(`INSERT INTO disk_report_chunks VALUES (?,?,?,?)`, out.ID, chunk.Sequence, chunk.Digest, chunk.Data); err != nil {
		return out, err
	}
	_, err = tx.Exec(`UPDATE disk_reports SET total_bytes=total_bytes+?,next_sequence=next_sequence+1 WHERE id=?`, len(chunk.Data), out.ID)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) DiskReportComplete(machine, job string, req diskreport.Complete) (diskreport.Receipt, error) {
	out := diskreport.Receipt{ID: "report-" + job, Digest: req.Digest}
	tx, err := s.beginWrite(context.Background(), "disk_report_complete")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	spec, err := reportJob(tx, machine, job, s.now().UTC())
	if err != nil {
		return out, err
	}
	var completed sql.NullString
	var digest string
	var count int
	err = tx.QueryRow(`SELECT completed_at,digest,item_count FROM disk_reports WHERE id=? AND machine_id=?`, out.ID, machine).Scan(&completed, &digest, &count)
	if err == sql.ErrNoRows {
		return out, operatorError("BAD_REQUEST", "report has no chunks")
	}
	if err != nil {
		return out, err
	}
	if completed.Valid {
		if digest != req.Digest || count != req.ItemCount {
			return out, operatorError("REVISION_CONFLICT", "completion replay differs")
		}
		return out, tx.Commit()
	}
	rows, err := tx.Query(`SELECT data FROM disk_report_chunks WHERE report_id=? ORDER BY sequence`, out.ID)
	if err != nil {
		return out, err
	}
	var raw []byte
	for rows.Next() {
		var b []byte
		if err = rows.Scan(&b); err != nil {
			rows.Close()
			return out, err
		}
		raw = append(raw, b...)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	report, canonical, err := diskreport.Decode(raw)
	if err != nil {
		return out, operatorError("BAD_REQUEST", "invalid typed report")
	}
	var args struct {
		ID       string `json:"policy_id"`
		Digest   string `json:"policy_digest"`
		MaxItems int    `json:"max_items"`
	}
	_ = json.Unmarshal(spec.Args, &args)
	policy, _, _, err := CanonicalDiskPolicy(spec.Policy)
	if err != nil || report.PolicyID != args.ID || report.PolicyDigest != args.Digest || len(report.Items) > args.MaxItems || len(report.Items) > policy.ScanBudgets.MaxItems || report.Entries > policy.ScanBudgets.MaxEntries || req.ItemCount != len(report.Items) || req.Digest != diskreport.Digest(canonical) {
		return out, operatorError("BAD_REQUEST", "report completion binding mismatch")
	}
	sort.SliceStable(report.Items, func(a, b int) bool {
		x, y := report.Items[a], report.Items[b]
		if (x.LastUsed == "") != (y.LastUsed == "") {
			return x.LastUsed != ""
		}
		if x.AllocatedBytes != y.AllocatedBytes {
			return x.AllocatedBytes > y.AllocatedBytes
		}
		rank := map[string]int{"high": 0, "medium": 1, "low": 2}
		if x.Confidence != y.Confidence {
			return rank[x.Confidence] < rank[y.Confidence]
		}
		return x.LastUsed < y.LastUsed
	})
	for n, item := range report.Items {
		path := item.PrivatePath
		item = diskreport.StoredItem(item)
		item.PrivatePath = ""
		if _, err = tx.Exec(`INSERT INTO disk_report_items VALUES (?,?,?,?,?)`, out.ID, n, item.ID, path, string(mustScriptJSON(item))); err != nil {
			return out, err
		}
	}
	// Completed uploads retain digest receipts for replay, not a second raw-path copy.
	if _, err = tx.Exec(`UPDATE disk_report_chunks SET data=X'' WHERE report_id=?`, out.ID); err != nil {
		return out, err
	}
	for n, notice := range report.Notices {
		report.Notices[n] = diskreport.ScrubDisplay(notice)
	}
	for n, root := range report.InaccessibleRoots {
		report.InaccessibleRoots[n] = diskreport.ScrubDisplay(root)
	}
	report.Items = []diskreport.Item{}
	_, err = tx.Exec(`UPDATE disk_reports SET completed_at=?,digest=?,metadata=?,item_count=? WHERE id=?`, fmtTime(s.now().UTC()), req.Digest, string(mustScriptJSON(report)), req.ItemCount, out.ID)
	if err != nil {
		return out, err
	}
	if err = s.recordAuditTx(tx, AuditEntry{At: s.now().UTC(), Action: "disk_report_complete", MachineID: machine, Subject: out.ID, OK: true, Detail: fmt.Sprintf("digest=%s items=%d", req.Digest, req.ItemCount)}); err != nil {
		return out, err
	}
	return out, tx.Commit()
}
func (s *Store) DiskReports(machine string) ([]DiskReportSummary, error) {
	rows, err := s.rdb.Query(`SELECT id,job_id,machine_id,created_at,digest,item_count,metadata FROM disk_reports WHERE completed_at IS NOT NULL AND created_at>=? AND (?='' OR machine_id=?) ORDER BY created_at DESC,id DESC LIMIT 100`, fmtTime(s.now().UTC().Add(-30*24*time.Hour)), machine, machine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiskReportSummary{}
	for rows.Next() {
		var v DiskReportSummary
		var meta string
		if err = rows.Scan(&v.ID, &v.JobID, &v.MachineID, &v.CreatedAt, &v.Digest, &v.ItemCount, &meta); err != nil {
			return nil, err
		}
		if err = json.Unmarshal([]byte(meta), &v.Report); err != nil {
			return nil, err
		}
		v.Report = diskreport.PublicReport(v.Report)
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) DiskReport(id, cursor string, limit int, private bool) (DiskReportPage, error) {
	var out DiskReportPage
	var meta string
	start := 0
	var err error
	if cursor != "" {
		start, err = strconv.Atoi(cursor)
	}
	if err != nil || start < 0 || limit < 1 || limit > 100 {
		return out, operatorError("BAD_REQUEST", "invalid report pagination")
	}
	err = s.rdb.QueryRow(`SELECT id,job_id,machine_id,created_at,digest,item_count,metadata FROM disk_reports WHERE id=? AND completed_at IS NOT NULL AND created_at>=?`, id, fmtTime(s.now().UTC().Add(-30*24*time.Hour))).Scan(&out.ID, &out.JobID, &out.MachineID, &out.CreatedAt, &out.Digest, &out.ItemCount, &meta)
	if err == sql.ErrNoRows {
		return out, operatorError("NOT_FOUND", "report not found")
	}
	if err != nil {
		return out, err
	}
	if err = json.Unmarshal([]byte(meta), &out.Report); err != nil {
		return out, err
	}
	if !private {
		out.Report = diskreport.PublicReport(out.Report)
	}
	rows, err := s.rdb.Query(`SELECT body,private_path FROM disk_report_items WHERE report_id=? AND position>=? ORDER BY position LIMIT ?`, id, start, limit+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	out.Items = []diskreport.Item{}
	for rows.Next() {
		var body, path string
		if err = rows.Scan(&body, &path); err != nil {
			return out, err
		}
		if len(out.Items) == limit {
			out.NextCursor = strconv.Itoa(start + limit)
			break
		}
		var item diskreport.Item
		if err = json.Unmarshal([]byte(body), &item); err != nil {
			return out, err
		}
		item.PrivatePath = diskreport.ScrubDisplay(path)
		if !private {
			item = diskreport.PublicItem(item)
		}
		out.Items = append(out.Items, item)
	}
	return out, rows.Err()
}
func (s *Store) PruneDiskReports(now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "prune_disk_reports")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM disk_reports WHERE (completed_at IS NULL AND created_at<?) OR (completed_at IS NOT NULL AND created_at<?)`, fmtTime(now.Add(-24*time.Hour)), fmtTime(now.Add(-30*24*time.Hour))); err != nil {
		return err
	}
	if _, err = tx.Exec(`DELETE FROM disk_deep_trigger_slots WHERE slot<?`, fmtTime(now.Add(-30*24*time.Hour))); err != nil {
		return err
	}
	return tx.Commit()
}
