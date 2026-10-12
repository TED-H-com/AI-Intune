package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"math/big"
	"time"
)

// deepAvailableTx coalesces all entry points, including queued scans and weekly
// schedules, using job creation time in the same SQLite writer transaction.
func deepAvailableTx(tx interface{ QueryRow(string, ...any) *sql.Row }, machine string, now time.Time) (bool, error) {
	var count int
	err := tx.QueryRow(`SELECT COUNT(*) FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.machine_id=? AND d.resource_kind='script_v1' AND d.resource_id='disk-deep-report-v1' AND (j.created_at>? OR j.state IN ('not_started','claimed','running','verifying'))`, machine, fmtTime(now.Add(-6*time.Hour))).Scan(&count)
	return count == 0, err
}
func (s *Store) ReconcileDiskPressure(now time.Time) error {
	rows, err := s.rdb.Query(`SELECT m.machine_id FROM machine_registry m WHERE m.expected=1 AND m.retired_at IS NULL AND EXISTS (SELECT 1 FROM machine_checkins c WHERE c.machine_id=m.machine_id AND c.received_at>=? AND c.received_at<=? AND c.sent_at>=? AND c.sent_at<=?)`, fmtTime(now.Add(-15*time.Minute)), fmtTime(now), fmtTime(now.Add(-15*time.Minute)), fmtTime(now))
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, id := range ids {
		if err = s.reconcileDiskPressureMachine(id, now.UTC()); err != nil {
			return err
		}
	}
	return s.PruneDiskReports(now)
}
func (s *Store) reconcileDiskPressureMachine(id string, now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "disk_pressure")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	slot := fmtTime(now.Truncate(time.Minute))
	var eligible, existing int
	if err = tx.QueryRow(`SELECT COUNT(*) FROM machine_registry WHERE machine_id=? AND expected=1 AND retired_at IS NULL`, id).Scan(&eligible); err != nil {
		return err
	}
	if eligible == 0 {
		return nil
	}
	if err = tx.QueryRow(`SELECT COUNT(*) FROM disk_deep_trigger_slots WHERE machine_id=? AND slot=?`, id, slot).Scan(&existing); err != nil {
		return err
	}
	if existing > 0 {
		return nil
	}
	outcome := "below_threshold"
	job := ""
	decide := func() error {
		// Routine evaluations leave no durable rows. Record one coalesce decision
		// per six-hour interval, rather than repeating it every scheduler minute.
		if outcome != "enqueued" && outcome != "coalesced" {
			return nil
		}
		if outcome == "coalesced" {
			var count int
			if e := tx.QueryRow(`SELECT COUNT(*) FROM disk_deep_trigger_slots WHERE machine_id=? AND outcome='coalesced' AND slot>? AND slot>=COALESCE((SELECT MAX(slot) FROM disk_deep_trigger_slots WHERE machine_id=? AND outcome='enqueued'),'')`, id, fmtTime(now.Add(-6*time.Hour)), id).Scan(&count); e != nil {
				return e
			}
			if count > 0 {
				return nil
			}
		}
		if _, e := tx.Exec(`INSERT INTO disk_deep_trigger_slots(machine_id,slot,outcome,job_id) VALUES (?,?,?,NULLIF(?,''))`, id, slot, outcome, job); e != nil {
			return e
		}
		if e := s.recordAuditTx(tx, AuditEntry{At: now, Action: "disk_pressure_trigger", MachineID: id, Subject: slot, AuthSubject: "scheduler:disk-pressure", OK: true, Detail: outcome}); e != nil {
			return e
		}
		return tx.Commit()
	}
	var total, free int64
	var sent, received string
	var capable sql.NullBool
	err = tx.QueryRow(`SELECT c.disk_total_bytes,c.disk_free_bytes,c.sent_at,c.received_at,cap.supported FROM machine_checkins c LEFT JOIN machine_job_capabilities cap ON cap.machine_id=c.machine_id AND cap.sent_at=c.sent_at AND cap.capability='disk_ops_v2' WHERE c.machine_id=? ORDER BY c.received_at DESC,c.rowid DESC LIMIT 1`, id).Scan(&total, &free, &sent, &received, &capable)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return err
	}
	if !capable.Valid || !capable.Bool {
		outcome = "skipped_unavailable"
		return decide()
	}
	observed, e := time.Parse(time.RFC3339Nano, sent)
	receipt, e2 := time.Parse(time.RFC3339Nano, received)
	if e != nil || e2 != nil || observed.After(now) || receipt.After(now) || now.Sub(observed) > 15*time.Minute || now.Sub(receipt) > 15*time.Minute || total <= 0 || free < 0 || free > total {
		outcome = "stale_observation"
		return decide()
	}
	// Use the machine's approved schedule policy first. With exactly one active
	// policy it is unambiguous; multiple unassigned policies require configuration.
	var policyID, body, digest string
	var argsRaw string
	err = tx.QueryRow(`SELECT args FROM schedules WHERE enabled=1 AND script_id='disk-deep-report-v1' AND EXISTS(SELECT 1 FROM json_each(targets) WHERE value=?) ORDER BY id LIMIT 1`, id).Scan(&argsRaw)
	if err == nil {
		var a struct {
			ID     string `json:"policy_id"`
			Digest string `json:"policy_digest"`
		}
		_ = json.Unmarshal([]byte(argsRaw), &a)
		policyID = a.ID
		digest = a.Digest
		err = tx.QueryRow(`SELECT body FROM ops_policies WHERE id=? AND digest=? AND superseded_at IS NULL`, policyID, digest).Scan(&body)
	} else if err == sql.ErrNoRows {
		err = tx.QueryRow(`SELECT id,body,digest FROM ops_policies WHERE superseded_at IS NULL AND (SELECT COUNT(*) FROM ops_policies WHERE superseded_at IS NULL)=1`).Scan(&policyID, &body, &digest)
	}
	if err == sql.ErrNoRows {
		outcome = "policy_unassigned"
		return decide()
	}
	if err != nil {
		return err
	}
	policy, canonical, actual, err := CanonicalDiskPolicy(json.RawMessage(body))
	if err != nil || digest != actual {
		outcome = "policy_invalid"
		return decide()
	}
	// Compare the ratio, not a rounded integer percentage: strictly above.
	usedRatio := new(big.Int).Mul(big.NewInt(total-free), big.NewInt(100))
	thresholdRatio := new(big.Int).Mul(big.NewInt(total), big.NewInt(int64(policy.Thresholds.DeepReportAbovePercent)))
	if usedRatio.Cmp(thresholdRatio) <= 0 {
		return decide()
	}
	available, err := deepAvailableTx(tx, id, now)
	if err != nil {
		return err
	}
	if !available {
		outcome = "coalesced"
		return decide()
	}
	entry, _ := scriptcatalog.Lookup("disk-deep-report-v1")
	args := mustScriptJSON(map[string]any{"policy_id": policyID, "policy_digest": digest, "max_items": policy.ScanBudgets.MaxItems})
	req := ScriptRunRequest{ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: args, Targets: []string{id}, TimeoutSeconds: 600, Reason: "fresh disk pressure"}
	if err = s.diskSafeGateTx(tx, req, entry); err != nil {
		outcome = "skipped_unavailable"
		return decide()
	}
	if err = validateScriptTargetsTx(tx, req, entry); err != nil {
		outcome = "skipped_unavailable"
		return decide()
	}
	raw := mustScriptJSON(scriptcatalog.Spec{Policy: canonical, ExecutionMode: "read", Kind: scriptcatalog.Kind, ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: args})
	desired, revision, err := createDesiredStateTx(tx, "machine", id, scriptcatalog.Kind, entry.ID, string(raw), "scheduler:disk-pressure", now)
	if err != nil {
		return err
	}
	job, err = createManagedJobTx(tx, id, desired, revision, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(raw), ExecutionTimeout: 600}, now)
	if err != nil {
		return err
	}
	outcome = "enqueued"
	return decide()
}
func DiskDeepScheduleTemplate(policyID, digest, machine string, hour, minute int) (ScheduleRequest, error) {
	if hour < 0 || hour > 23 || minute < 0 || minute > 59 {
		return ScheduleRequest{}, operatorError("BAD_REQUEST", "invalid UTC offset")
	}
	e, _ := scriptcatalog.Lookup("disk-deep-report-v1")
	return ScheduleRequest{Name: "deep-disk-" + scriptcatalog.Digest([]byte(machine))[:12], ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: mustScriptJSON(map[string]any{"policy_id": policyID, "policy_digest": digest, "max_items": 500}), Targets: []string{machine}, Cron: fmt.Sprintf("%d %d * * 0", minute, hour), Enabled: true}, nil
}
