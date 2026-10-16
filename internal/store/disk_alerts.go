package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type DiskAlert struct {
	ClearedReason         string     `json:"cleared_reason,omitempty"`
	ID                    string     `json:"id"`
	MachineID             string     `json:"machine_id"`
	ConditionKey          string     `json:"condition_key"`
	Severity              string     `json:"severity"`
	OpenedAt              time.Time  `json:"opened_at"`
	ClearedAt             *time.Time `json:"cleared_at,omitempty"`
	AcknowledgedAt        *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgementReason string     `json:"acknowledgement_reason,omitempty"`
}

func (s *Store) DiskAlertsList(machine string) ([]DiskAlert, error) {
	rows, err := s.rdb.Query(`SELECT id,machine_id,condition_key,severity,opened_at,cleared_at,acknowledged_at,acknowledgement_reason,cleared_reason FROM disk_alerts WHERE (?='' OR machine_id=?) ORDER BY (cleared_at IS NULL) DESC,opened_at DESC LIMIT 500`, machine, machine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiskAlert{}
	for rows.Next() {
		var a DiskAlert
		var opened string
		var cleared, ack sql.NullString
		if err = rows.Scan(&a.ID, &a.MachineID, &a.ConditionKey, &a.Severity, &opened, &cleared, &ack, &a.AcknowledgementReason, &a.ClearedReason); err != nil {
			return nil, err
		}
		a.OpenedAt = parseTime(opened)
		if cleared.Valid {
			t := parseTime(cleared.String)
			a.ClearedAt = &t
		}
		if ack.Valid {
			t := parseTime(ack.String)
			a.AcknowledgedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DiskAlertReading evaluates an independent condition against measured evidence.
// nil is unknown: it breaks the clearing sequence and never resolves an episode.
// Equality at threshold-2 is deliberately insufficient: clearing is below it.
func (s *Store) DiskAlertReading(machine, key, severity string, value *int, threshold int, measured time.Time) error {
	tx, err := s.beginWrite(context.Background(), "disk_alert_reading")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var id, last string
	var below sql.NullString
	err = tx.QueryRow(`SELECT id,below_since,last_reading FROM disk_alerts WHERE machine_id=? AND condition_key=? AND cleared_at IS NULL`, machine, key).Scan(&id, &below, &last)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if id == "" {
		if value == nil || *value < threshold {
			return nil
		}
		if strings.HasPrefix(key, "mount:") {
			var open int
			if err = tx.QueryRow(`SELECT COUNT(*) FROM disk_alerts WHERE machine_id=? AND cleared_at IS NULL AND condition_key LIKE 'mount:%'`, machine).Scan(&open); err != nil {
				return err
			}
			if open >= 8 {
				return nil
			}
		}
		id = "disk-" + scriptcatalog.Digest([]byte(machine + "\x00" + key + "\x00" + fmtTime(measured)))[:32]
		_, err = tx.Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,last_reading,last_seen_at) VALUES (?,?,?,?,?,?,?)`, id, machine, key, severity, fmtTime(measured), fmtTime(measured), fmtTime(measured))
		if err != nil {
			return err
		}
		return tx.Commit()
	}
	if !measured.After(parseTime(last)) {
		return nil
	}
	var next any
	if value != nil && *value < threshold-2 {
		if below.Valid && measured.Sub(parseTime(below.String)) >= 5*time.Minute {
			_, err = tx.Exec(`UPDATE disk_alerts SET cleared_at=?,last_reading=?,last_seen_at=? WHERE id=?`, fmtTime(measured), fmtTime(measured), fmtTime(measured), id)
			if err != nil {
				return err
			}
			return tx.Commit()
		}
		if below.Valid {
			next = below.String
		} else {
			next = fmtTime(measured)
		}
	}
	_, err = tx.Exec(`UPDATE disk_alerts SET below_since=?,last_reading=?,last_seen_at=CASE WHEN ? THEN ? ELSE last_seen_at END WHERE id=?`, next, fmtTime(measured), value != nil, fmtTime(measured), id)
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ReconcileDiskAlerts(now time.Time) error {
	if err := s.PruneDiskCanaryDays(now); err != nil {
		return err
	}
	if err := s.PruneDiskAlerts(now); err != nil {
		return err
	}
	rows, err := s.rdb.Query(`SELECT machine_id FROM machine_registry WHERE retired_at IS NULL`)
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
		status, e := s.DiskOpsStatus(id)
		if e != nil {
			return e
		}
		if e = s.diskEvidenceWarnings(id, now); e != nil {
			return e
		}
		if e = s.RecordDiskCanary(id, status, now); e != nil {
			return e
		}
		seen := map[string]bool{}
		for _, m := range status.Mounts {
			at, e := time.Parse(time.RFC3339, m.MeasuredAt)
			key := "mount:" + scriptcatalog.Digest([]byte(m.Mount))
			var value *int
			if e == nil && !at.After(now) && now.Sub(at) <= 15*time.Minute {
				v := m.Percent
				value = &v
			} else {
				at = now
			}
			for _, severity := range []string{"warn", "critical"} {
				threshold := status.Thresholds.WarnPercent
				if severity == "critical" {
					threshold = status.Thresholds.CriticalPercent
				}
				condition := key + ":" + severity
				seen[condition] = true
				if e = s.DiskAlertReading(id, condition, severity, value, threshold, at); e != nil {
					return e
				}
			}
		}

		// Delivery health is reconciled from open conditions, independently of the
		// eligible notification queue. A successful send/recovery leaves that queue
		// immediately, but its warning still needs two fresh clearing readings.
		for _, a := range status.Alerts {
			if a.ClearedAt == nil && a.Severity == "critical" {
				if e = s.DiskCriticalDeliveryWarning(id, a.ConditionKey, "disk-alert:"+a.ID, now); e != nil {
					return e
				}
			}
		}
		for _, a := range status.Alerts {
			if a.ClearedAt != nil || !strings.HasPrefix(a.ConditionKey, "delivery-failed:") {
				continue
			}
			key := strings.TrimPrefix(a.ConditionKey, "delivery-failed:")
			open := false
			for _, condition := range status.Alerts {
				if condition.ClearedAt == nil && condition.Severity == "critical" && condition.ConditionKey == key {
					open = true
					break
				}
			}
			if !open {
				v := 0
				if e = s.DiskAlertReading(id, a.ConditionKey, "warn", &v, 50, now); e != nil {
					return e
				}
			}
		}
		// Missing mounts invalidate the clearing sequence rather than disappear.
		for _, a := range status.Alerts {
			if a.ClearedAt == nil && strings.HasPrefix(a.ConditionKey, "mount:") && !seen[a.ConditionKey] {
				if e = s.DiskAlertReading(id, a.ConditionKey, a.Severity, nil, 100, now); e != nil {
					return e
				}
			}
		}
		for _, owner := range status.OwnershipRecords {
			if e = s.diskLocalLockWarning(id, owner.Scope); e != nil {
				return e
			}
			o := owner.Observation
			var dual, age *int
			at := now
			if o != nil && o.Known && !o.ReceivedAt.After(now) && now.Sub(o.ReceivedAt) <= 15*time.Minute {
				at = o.ReceivedAt
				d := 0
				if owner.State == "hub-owned" && (o.Enabled || o.Active || o.ServiceActive) {
					d = 100
				}
				dual = &d
				if o.SummaryAgeSeconds != nil {
					v := 0
					if *o.SummaryAgeSeconds > 48*3600 {
						v = 100
					}
					age = &v
				}
			}
			if e = s.DiskAlertReading(id, "dual-owner:"+owner.Scope, "warn", dual, 50, at); e != nil {
				return e
			}
			if e = s.DiskAlertReading(id, "summary-stale:"+owner.Scope, "warn", age, 50, at); e != nil {
				return e
			}
		}
		var pending int
		if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM ops_approvals WHERE machine_id=? AND state='pending' AND created_at<?`, id, fmtTime(now.Add(-24*time.Hour))).Scan(&pending); e != nil {
			return e
		}
		value := 0
		if pending > 0 {
			value = 100
		}
		if e = s.DiskAlertReading(id, "approvals-pending", "warn", &value, 50, now); e != nil {
			return e
		}
	}
	return s.ExpireMissingDiskMounts(now)
}

type DiskAlertAckRequest struct {
	ID            string    `json:"id"`
	Reason        string    `json:"reason"`
	ExpiresAt     time.Time `json:"expires_at"`
	PreviewDigest string    `json:"preview_digest"`
}
type DiskAlertAckResult struct {
	ID            string    `json:"id"`
	Reason        string    `json:"reason"`
	ExpiresAt     time.Time `json:"expires_at"`
	PreviewDigest string    `json:"preview_digest"`
	Replayed      bool      `json:"replayed"`
}

func (s *Store) DiskAlertAcknowledge(req DiskAlertAckRequest, apply bool, key string, a AuditEntry) (DiskAlertAckResult, error) {
	if strings.TrimSpace(req.Reason) != "" {
		normalizedReason, reasonErr := boundedtext.Reason(req.Reason)
		if reasonErr != nil {
			return DiskAlertAckResult{}, operatorError(OperatorCodeReasonRequired, reasonErr.Error())
		}
		req.Reason = normalizedReason
	}

	var out DiskAlertAckResult
	if err := humanDiskAdmin(a); err != nil {
		return out, err
	}
	if req.ID == "" || len([]rune(req.Reason)) > boundedtext.MaxReasonRunes || strings.TrimSpace(req.Reason) == "" || !validAuditReason(req.Reason) || strings.IndexFunc(req.Reason, unicode.IsControl) >= 0 {
		return out, operatorError("BAD_REQUEST", "safe reason and alert ID required")
	}
	now := s.now().UTC()
	if !apply {
		req.ExpiresAt = now.Add(30 * time.Minute)
	}
	supplied := req.PreviewDigest
	req.PreviewDigest = ""
	raw, _ := json.Marshal(req)
	out = DiskAlertAckResult{ID: req.ID, Reason: req.Reason, ExpiresAt: req.ExpiresAt, PreviewDigest: "sha256:" + scriptcatalog.Digest(raw)}
	if apply && (key == "" || supplied != out.PreviewDigest) {
		return out, operatorError("PRECONDITION_FAILED", "fresh preview binding required")
	}
	tx, err := s.beginWrite(context.Background(), "disk_alert_ack")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	if apply {
		var digest, body string
		err = tx.QueryRow(`SELECT digest,body FROM disk_handoff_receipts WHERE actor=? AND idempotency_key=?`, a.AuthSubject, key).Scan(&digest, &body)
		if err == nil {
			if digest != out.PreviewDigest {
				return out, operatorError("REVISION_CONFLICT", "idempotency conflict")
			}
			err = json.Unmarshal([]byte(body), &out)
			out.Replayed = true
			if err != nil {
				return out, err
			}
			a.Action = "disk_alert_ack"
			a.Subject = req.ID
			a.RequestDigest = out.PreviewDigest
			a.IdempotencyKey = key
			a.OK = true
			a.Detail = "idempotent replay"
			if err = s.recordAuditTx(tx, a); err != nil {
				return out, err
			}
			return out, tx.Commit()
		}
		if err != sql.ErrNoRows {
			return out, err
		}
	}
	if apply && (!req.ExpiresAt.After(now) || req.ExpiresAt.After(now.Add(30*time.Minute))) {
		return out, operatorError("PRECONDITION_FAILED", "preview expired")
	}
	var machine string
	if err = tx.QueryRow(`SELECT machine_id FROM disk_alerts WHERE id=?`, req.ID).Scan(&machine); err != nil {
		return out, operatorError("NOT_FOUND", "alert not found")
	}
	if !apply {
		return out, nil
	}
	if _, err = tx.Exec(`UPDATE disk_alerts SET acknowledged_at=?,acknowledgement_reason=? WHERE id=?`, fmtTime(now), req.Reason, req.ID); err != nil {
		return out, err
	}
	body, _ := json.Marshal(out)
	if _, err = tx.Exec(`INSERT INTO disk_handoff_receipts(actor,idempotency_key,digest,body) VALUES (?,?,?,?)`, a.AuthSubject, key, out.PreviewDigest, string(body)); err != nil {
		return out, err
	}
	a.Action = "disk_alert_ack"
	a.MachineID = machine
	a.Subject = req.ID
	a.RequestDigest = out.PreviewDigest
	a.IdempotencyKey = key
	a.OK = true
	a.Detail = req.Reason
	if err = s.recordAuditTx(tx, a); err != nil {
		return out, err
	}
	return out, tx.Commit()
}

type DiskSupervision struct {
	OpenWarn            int            `json:"open_warn"`
	OpenCritical        int            `json:"open_critical"`
	OldestOpenCritical  *time.Time     `json:"oldest_open_critical,omitempty"`
	OwnershipStates     map[string]int `json:"ownership_states"`
	CanaryAgreementDays int            `json:"canary_agreement_days"`
}

// The closed supervision wire contract represents ownership counts as an object,
// including zero-value DTOs used by clients and response producers.
func (d DiskSupervision) MarshalJSON() ([]byte, error) {
	type wire DiskSupervision
	if d.OwnershipStates == nil {
		d.OwnershipStates = map[string]int{}
	}
	return json.Marshal(wire(d))
}

func (s *Store) DiskSupervision(machine string) (DiskSupervision, error) {
	out := DiskSupervision{OwnershipStates: map[string]int{}}
	var oldest sql.NullString
	err := s.rdb.QueryRow(`SELECT COALESCE(SUM(severity='warn'),0),COALESCE(SUM(severity='critical'),0),MIN(CASE WHEN severity='critical' THEN opened_at END) FROM disk_alerts WHERE cleared_at IS NULL AND (?='' OR machine_id=?)`, machine, machine).Scan(&out.OpenWarn, &out.OpenCritical, &oldest)
	if err != nil {
		return out, err
	}
	if oldest.Valid {
		t := parseTime(oldest.String)
		out.OldestOpenCritical = &t
	}
	rows, err := s.rdb.Query(`SELECT state,COUNT(*) FROM disk_ownership WHERE (?='' OR machine_id=?) GROUP BY state`, machine, machine)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var state string
		var n int
		if err = rows.Scan(&state, &n); err != nil {
			rows.Close()
			return out, err
		}
		out.OwnershipStates[state] = n
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	err = s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_canary_days WHERE agreement=1 AND (?='' OR machine_id=?)`, machine, machine).Scan(&out.CanaryAgreementDays)
	return out, err
}

func (s *Store) diskEvidenceWarnings(machine string, now time.Time) error {
	rows, err := s.rdb.Query(`SELECT v.stdout_excerpt FROM verification_results v JOIN jobs j ON j.job_id=v.job_id JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.machine_id=? AND d.resource_id='disk-safe-clean-v2' AND v.rule_id='script_v1' AND v.producer_id=? AND v.evidence_role=? AND v.producer_kind=? AND v.authority=? ORDER BY v.rowid DESC LIMIT 2`, machine, machine, JobVerificationRoleExecutor, JobVerificationProducerExecutorAgent, JobVerificationAuthorityMachineLease)
	if err != nil {
		return err
	}
	skips := 0
	truncated := false
	count := 0
	var latest time.Time
	scope := "user"
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var v DiskSafeEnvelope
		if len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &v) != nil {
			continue
		}
		count++
		if count == 1 {
			latest, _ = time.Parse(time.RFC3339, v.Summary.TS)
			if v.Summary.Scope == "root" {
				scope = "root"
			}
			for _, c := range v.Summary.Categories {
				if strings.Contains(c.Note, "budget") || strings.Contains(c.Note, "truncated") {
					truncated = true
				}
			}
		}
		locked := false
		for _, c := range v.Summary.Categories {
			if c.Status == "skipped" && strings.Contains(c.Note, "lock") {
				locked = true
			}
		}
		if locked {
			skips++
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count > 0 && !latest.IsZero() {
		scan := 0
		if truncated {
			scan = 100
		}
		if err = s.DiskAlertReading(machine, "truncated-safe-scan", "warn", &scan, 50, latest); err != nil {
			return err
		}
		value := 0
		if skips == 2 {
			value = 100
		}
		if err = s.DiskAlertReading(machine, "consecutive-lock-skips:"+scope, "warn", &value, 50, latest); err != nil {
			return err
		}
	}
	reports, err := s.DiskReports(machine)
	if err != nil {
		return err
	}
	if len(reports) > 0 {
		at, e := time.Parse(time.RFC3339, reports[0].CreatedAt)
		if e == nil {
			value := 0
			if reports[0].Report.Truncated {
				value = 100
			}
			if err = s.DiskAlertReading(machine, "truncated-scan", "warn", &value, 50, at); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *Store) DiskCriticalDeliveryWarning(machine, episode, kind string, now time.Time) error {
	var first sql.NullString
	err := s.rdb.QueryRow(`SELECT MIN(sent_at) FROM notifications WHERE kind=? AND delivered=0 AND rowid>COALESCE((SELECT MAX(rowid) FROM notifications WHERE kind=? AND delivered=1),0)`, kind, kind).Scan(&first)
	if err != nil {
		return err
	}
	value := 0
	if first.Valid && now.Sub(parseTime(first.String)) >= 15*time.Minute {
		value = 100
	}
	return s.DiskAlertReading(machine, "delivery-failed:"+episode, "warn", &value, 50, now)
}

const diskAlertClearedRetention = 90 * 24 * time.Hour

func (s *Store) PruneDiskAlerts(now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "disk_alert_retention")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM disk_alerts WHERE cleared_at IS NOT NULL AND cleared_at<?`, fmtTime(now.Add(-diskAlertClearedRetention))); err != nil {
		return err
	}
	return tx.Commit()
}

// Priority + ID is a seek cursor: ID alone would skip recovery entries after
// an open critical with a lexically larger ID. No public API exposes this cursor.
func DiskAlertNotificationCursor(a DiskAlert) string {
	priority := 0
	if a.Severity != "critical" {
		priority = 1
	}
	if a.ClearedAt != nil {
		priority += 2
	}
	return fmt.Sprintf("%d:%s", priority, a.ID)
}
func (s *Store) DiskAlertNotificationBatch(after string) ([]DiskAlert, error) {
	return s.DiskAlertNotificationBatchSeverity(after, "")
}
func (s *Store) DiskAlertNotificationBatchSeverity(after, severity string, times ...time.Time) ([]DiskAlert, error) {
	now := s.now().UTC()
	if len(times) > 0 {
		now = times[0].UTC()
	}
	priority := -1
	id := ""
	if after != "" {
		p, key, ok := strings.Cut(after, ":")
		var err error
		priority, err = strconv.Atoi(p)
		if !ok || err != nil || priority < 0 || priority > 3 || key == "" {
			return nil, operatorError("BAD_REQUEST", "invalid internal alert cursor")
		}
		id = key
	}
	// Only unresolved due notifications or unsent recoveries reach the notifier.
	// The ledger's (kind,delivered,sent_at) index supplies each correlated lookup;
	// historical successes are not materialized or visited by the Go sweep.
	rows, err := s.rdb.Query(`SELECT a.id,a.machine_id,a.condition_key,a.severity,a.opened_at,a.cleared_at,a.cleared_reason,
 CASE WHEN a.cleared_at IS NULL AND a.severity='critical' THEN 0 WHEN a.cleared_at IS NULL THEN 1 WHEN a.severity='critical' THEN 2 ELSE 3 END AS priority
 FROM disk_alerts a WHERE (?='' OR a.severity=?)
 AND (CASE WHEN a.cleared_at IS NULL AND a.severity='critical' THEN 0 WHEN a.cleared_at IS NULL THEN 1 WHEN a.severity='critical' THEN 2 ELSE 3 END,a.id)>(?,?)
 AND ((a.cleared_at IS NULL AND
  ((a.severity='critical' AND NOT EXISTS(SELECT 1 FROM notifications n WHERE n.kind='disk-alert:'||a.id AND n.delivered=1 AND julianday(n.sent_at)>julianday(?)))
   OR (a.severity='warn' AND NOT EXISTS(SELECT 1 FROM notifications n WHERE n.kind='disk-alert:'||a.id AND n.delivered=1))))
 OR (a.cleared_at IS NOT NULL AND a.cleared_at>=?
  AND EXISTS(SELECT 1 FROM notifications n WHERE n.kind='disk-alert:'||a.id AND n.delivered=1)
  AND NOT EXISTS(SELECT 1 FROM notifications n WHERE n.kind='disk-alert:'||a.id||':recovery' AND n.delivered=1)
  AND NOT EXISTS(SELECT 1 FROM disk_alerts newer WHERE newer.machine_id=a.machine_id AND newer.condition_key=a.condition_key AND (newer.cleared_at IS NULL OR newer.rowid>a.rowid))))
 AND NOT EXISTS(SELECT 1 FROM disk_alert_delivery_reservations r WHERE r.machine_id=a.machine_id AND r.condition_key=a.condition_key AND r.lane=CASE WHEN a.cleared_at IS NOT NULL THEN 'recovery' ELSE a.severity END AND (r.delivered=1 OR r.completed=0) AND r.reserved_at>CASE WHEN a.cleared_at IS NULL AND a.severity='critical' THEN ? ELSE ? END)
 ORDER BY priority,a.id LIMIT 100`, severity, severity, priority, id, diskReceiptTime(now.Add(-6*time.Hour)), fmtTime(now.Add(-diskAlertClearedRetention)), diskReceiptTime(now.Add(-6*time.Hour)), diskReceiptTime(now.Add(-24*time.Hour)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DiskAlert{}
	for rows.Next() {
		var a DiskAlert
		var opened string
		var cleared sql.NullString
		var p int
		if err = rows.Scan(&a.ID, &a.MachineID, &a.ConditionKey, &a.Severity, &opened, &cleared, &a.ClearedReason, &p); err != nil {
			return nil, err
		}
		a.OpenedAt = parseTime(opened)
		if cleared.Valid {
			t := parseTime(cleared.String)
			a.ClearedAt = &t
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) diskLocalLockWarning(machine, scope string) error {
	rows, err := s.rdb.Query(`SELECT body FROM disk_timer_observations WHERE machine_id=? AND scope=? AND json_extract(body,'$.summary_lock_skipped') IS NOT NULL AND json_extract(body,'$.summary_at') IS NOT NULL GROUP BY json_extract(body,'$.summary_at') ORDER BY MAX(receipt_seq) DESC LIMIT 2`, machine, scope)
	if err != nil {
		return err
	}
	count, skips := 0, 0
	var at time.Time
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return err
		}
		var o model.DiskTimerObservation
		if json.Unmarshal([]byte(raw), &o) != nil || o.SummaryLockSkipped == nil || o.SummaryAt.IsZero() {
			continue
		}
		if count == 0 {
			at = o.SummaryAt
		}
		count++
		if *o.SummaryLockSkipped {
			skips++
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if count < 2 {
		return nil
	}
	value := 0
	if skips == 2 {
		value = 100
	}
	return s.DiskAlertReading(machine, "consecutive-lock-skips:"+scope, "warn", &value, 50, at)
}
