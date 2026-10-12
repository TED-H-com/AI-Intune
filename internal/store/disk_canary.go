package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"
)

type DiskCanaryDay struct {
	Day                 string `json:"day"`
	LocalSummaryAt      string `json:"local_summary_at"`
	HubSummaryAt        string `json:"hub_summary_at"`
	LocalCandidateBytes int64  `json:"local_candidate_bytes"`
	HubCandidateBytes   int64  `json:"hub_candidate_bytes"`
	Agreement           bool   `json:"agreement"`
	PolicyDigest        string `json:"policy_digest"`
}
type DiskCanary struct {
	RequiredDays int             `json:"required_days"`
	AgreedDays   int             `json:"agreed_days"`
	Satisfied    bool            `json:"satisfied"`
	Days         []DiskCanaryDay `json:"days"`
}

func (s *Store) DiskCanaryGet(machine, scope string, now time.Time) (DiskCanary, error) {
	now = now.UTC()
	out := DiskCanary{RequiredDays: 7, Days: []DiskCanaryDay{}}
	status, err := s.diskCanaryPolicy(machine, scope)
	if err != nil {
		return out, err
	}
	if status.CanaryDays > 0 {
		out.RequiredDays = status.CanaryDays
	}
	policyRaw, _ := json.Marshal(status)
	_, _, currentDigest, err := CanonicalDiskPolicy(policyRaw)
	if err != nil {
		return out, err
	}
	rows, err := s.rdb.Query(`SELECT day,local_summary_at,hub_summary_at,local_candidate_bytes,hub_candidate_bytes,agreement,policy_digest FROM disk_canary_days WHERE machine_id=? AND scope=? AND day>=? AND day<=? ORDER BY day`, machine, scope, now.AddDate(0, 0, 1-out.RequiredDays).Format("2006-01-02"), now.UTC().Format("2006-01-02"))
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var d DiskCanaryDay
		if err = rows.Scan(&d.Day, &d.LocalSummaryAt, &d.HubSummaryAt, &d.LocalCandidateBytes, &d.HubCandidateBytes, &d.Agreement, &d.PolicyDigest); err != nil {
			return out, err
		}
		out.Days = append(out.Days, d)
		if d.Agreement && d.PolicyDigest == currentDigest {
			out.AgreedDays++
		}
	}
	out.Satisfied = out.AgreedDays >= out.RequiredDays
	return out, rows.Err()
}
func (s *Store) diskCanaryPolicy(machine, scope string) (DiskPolicy, error) {
	var body string
	err := s.rdb.QueryRow(`SELECT p.body FROM schedules s JOIN ops_policies p ON p.id=json_extract(s.args,'$.policy_id') AND p.digest=json_extract(s.args,'$.policy_digest') AND p.superseded_at IS NULL WHERE s.script_id IN ('disk-safe-preview-v2','disk-safe-clean-v2') AND json_extract(s.args,'$.scope')=? AND EXISTS(SELECT 1 FROM json_each(s.targets) WHERE value=?) ORDER BY CASE WHEN s.script_id='disk-safe-clean-v2' THEN 0 ELSE 1 END,s.id LIMIT 1`, scope, machine).Scan(&body)
	if err == sql.ErrNoRows {
		return DefaultDiskPolicy(), nil
	}
	if err != nil {
		return DiskPolicy{}, err
	}
	p, _, _, err := CanonicalDiskPolicy([]byte(body))
	return p, err
}
func (s *Store) RecordDiskCanary(machine string, status DiskOpsStatus, now time.Time) error {
	if status.Preview == nil {
		return nil
	}
	p := status.Preview
	at, e := time.Parse(time.RFC3339, p.Summary.TS)
	if e != nil || at.After(now) || now.Sub(at) > 24*time.Hour {
		return nil
	}
	for _, owner := range status.OwnershipRecords {
		if owner.State != "local-owned" || owner.Scope != p.Summary.Scope || owner.Observation == nil {
			continue
		}
		local := owner.Observation
		if local.SummaryCandidateBytes == nil || local.SummaryAt.IsZero() || local.SummaryAt.After(now) || local.SummaryAt.UTC().Format("2006-01-02") != at.UTC().Format("2006-01-02") {
			continue
		}
		policy, e := s.diskCanaryPolicy(machine, owner.Scope)
		if e != nil {
			return e
		}
		rawPolicy, _ := json.Marshal(policy)
		_, _, currentDigest, e := CanonicalDiskPolicy(rawPolicy)
		if e != nil || currentDigest != p.Operation.PolicyDigest {
			continue
		}
		// Evidence ordering uses Hub receipts, never agent summary timestamps.
		received := p.ReceivedAt
		if local.ReceivedAt.After(received) {
			received = local.ReceivedAt
		}
		if received.IsZero() || received.After(now) {
			continue
		}
		agreement := *local.SummaryCandidateBytes == p.Summary.CandidateBytes
		tx, err := s.beginWrite(context.Background(), "disk_canary")
		if err != nil {
			return err
		}
		_, err = tx.Exec(`INSERT INTO disk_canary_days(machine_id,scope,day,local_summary_at,hub_summary_at,local_candidate_bytes,hub_candidate_bytes,agreement,policy_digest,received_at) VALUES (?,?,?,?,?,?,?,?,?,?) ON CONFLICT(machine_id,scope,day) DO UPDATE SET local_summary_at=excluded.local_summary_at,hub_summary_at=excluded.hub_summary_at,local_candidate_bytes=excluded.local_candidate_bytes,hub_candidate_bytes=excluded.hub_candidate_bytes,agreement=CASE WHEN disk_canary_days.policy_digest<>excluded.policy_digest THEN excluded.agreement ELSE disk_canary_days.agreement AND excluded.agreement END,policy_digest=excluded.policy_digest,received_at=excluded.received_at WHERE excluded.received_at>disk_canary_days.received_at`, machine, owner.Scope, at.UTC().Format("2006-01-02"), fmtTime(local.SummaryAt), fmtTime(at), *local.SummaryCandidateBytes, p.Summary.CandidateBytes, agreement, p.Operation.PolicyDigest, received.UTC().Format("2006-01-02T15:04:05.000000000Z"))
		if err != nil {
			tx.Rollback()
			return err
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

// Retain the maximum supported policy window (90 days), including today.
// Each scheduler tick deletes at most 1,000 expired rows through the day index.
func (s *Store) PruneDiskCanaryDays(now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "disk_canary_retention")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`DELETE FROM disk_canary_days WHERE rowid IN (SELECT rowid FROM disk_canary_days WHERE day<? ORDER BY day LIMIT 1000)`, now.UTC().AddDate(0, 0, 1-90).Format("2006-01-02")); err != nil {
		return err
	}
	return tx.Commit()
}
