package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/model"
)

const diskTimerIngestionInterval = 30 * time.Second
const diskTimerHistoryLimit = 10
const diskTimerHistoryAge = 14 * 24 * time.Hour

func diskReceiptTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000000000Z") }

func (s *Store) DiskTimerTransitions(machine string) (map[string]model.DiskTimerTransition, error) {
	rows, err := s.rdb.Query(`SELECT scope,revision,transition_nonce FROM disk_ownership WHERE machine_id=? AND state='handoff-pending'`, machine)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]model.DiskTimerTransition{}
	for rows.Next() {
		var scope string
		var challenge model.DiskTimerTransition
		if err = rows.Scan(&scope, &challenge.Revision, &challenge.Nonce); err != nil {
			return nil, err
		}
		out[scope] = challenge
	}
	return out, rows.Err()
}

// Only Hub receipt time/sequence orders timer evidence. Agent time is retained
// for display; the echoed challenge proves this observation follows handoff.
func (s *Store) recordDiskTimersTx(tx dbTx, machine string, c model.Checkin, received time.Time) error {
	if !c.DiskOpsV2 {
		return nil
	}
	for _, scope := range []string{"user", "root"} {
		if _, err := tx.Exec(`INSERT INTO disk_ownership(machine_id,scope,state,revision,changed_at) VALUES (?,?,'local-owned',0,?) ON CONFLICT(machine_id,scope) DO NOTHING`, machine, scope, diskReceiptTime(received)); err != nil {
			return err
		}
	}
	if len(c.DiskTimers) == 0 || len(c.DiskTimers) > 2 {
		return nil
	}
	var last string
	err := tx.QueryRow(`SELECT received_at FROM disk_timer_ingestion WHERE machine_id=?`, machine).Scan(&last)
	if err != nil && err != sql.ErrNoRows {
		return err
	}
	if err == nil && received.Sub(parseTime(last)) < diskTimerIngestionInterval {
		return nil
	}
	seen := map[string]bool{}
	accepted := false
	for _, o := range c.DiskTimers {
		if (o.Scope != "user" && o.Scope != "root") || seen[o.Scope] || o.ObservedAt.IsZero() || len(o.TransitionNonce) > 128 {
			continue
		}
		seen[o.Scope] = true
		if (o.SummaryAgeSeconds != nil && *o.SummaryAgeSeconds < 0) || (o.SummaryCandidateBytes != nil && *o.SummaryCandidateBytes < 0) {
			continue
		}
		o.ReceivedAt = received
		o.ReceiptSequence = 0 // Never trust wire-supplied receipts.
		raw, _ := json.Marshal(o)
		result, err := tx.Exec(`INSERT INTO disk_timer_observations(machine_id,scope,observed_at,received_at,body) VALUES (?,?,?,?,?)`, machine, o.Scope, diskReceiptTime(o.ObservedAt), diskReceiptTime(received), string(raw))
		if err != nil {
			return err
		}
		sequence, err := result.LastInsertId()
		if err != nil {
			return err
		}
		o.ReceiptSequence = sequence
		raw, _ = json.Marshal(o)
		if _, err = tx.Exec(`UPDATE disk_timer_observations SET body=? WHERE receipt_seq=?`, string(raw), sequence); err != nil {
			return err
		}
		accepted = true
		if o.Known && !o.Enabled && !o.Active && !o.ServiceActive && o.TransitionNonce != "" {
			var changed string
			err = tx.QueryRow(`SELECT changed_at FROM disk_ownership WHERE machine_id=? AND scope=? AND state='handoff-pending' AND revision=? AND transition_nonce=?`, machine, o.Scope, o.TransitionRevision, o.TransitionNonce).Scan(&changed)
			if err != nil && err != sql.ErrNoRows {
				return err
			}
			if err == sql.ErrNoRows || !received.After(parseTime(changed)) {
				continue
			}

			result, err = tx.Exec(`UPDATE disk_ownership SET state='hub-owned',revision=revision+1,changed_at=?,transition_nonce='' WHERE machine_id=? AND scope=? AND state='handoff-pending' AND revision=? AND transition_nonce=?`, diskReceiptTime(received), machine, o.Scope, o.TransitionRevision, o.TransitionNonce)
			if err != nil {
				return err
			}
			n, _ := result.RowsAffected()
			if n > 0 {
				if err = s.recordAuditTx(tx, AuditEntry{At: received, MachineID: machine, Action: "disk_ownership_observed", Subject: o.Scope, AuthSubject: "agent:" + machine, AuthCapability: "disk_ops_v2", AuthMethod: "machine_checkin", OK: true, Detail: "hub-owned: post-transition receipt echoed revision and nonce; local timer and service stopped"}); err != nil {
					return err
				}
			}
		}
	}
	if accepted {
		if _, err = tx.Exec(`INSERT INTO disk_timer_ingestion(machine_id,received_at) VALUES (?,?) ON CONFLICT(machine_id) DO UPDATE SET received_at=excluded.received_at`, machine, diskReceiptTime(received)); err != nil {
			return err
		}
	}
	return pruneDiskTimersTx(tx, received, machine)
}

func pruneDiskTimersTx(tx dbTx, now time.Time, machine string) error {
	// Preserve one latest receipt even when stale; bounded history expires by Hub
	// time, not attacker-controlled ObservedAt. The time cutoff uses its index.
	if _, err := tx.Exec(`DELETE FROM disk_timer_observations WHERE received_at<? AND receipt_seq NOT IN (SELECT MAX(receipt_seq) FROM disk_timer_observations GROUP BY machine_id,scope)`, diskReceiptTime(now.Add(-diskTimerHistoryAge))); err != nil {
		return err
	}
	if machine == "" {
		_, err := tx.Exec(`DELETE FROM disk_timer_observations WHERE receipt_seq IN (SELECT receipt_seq FROM (SELECT receipt_seq,ROW_NUMBER() OVER(PARTITION BY machine_id,scope ORDER BY receipt_seq DESC) n FROM disk_timer_observations) WHERE n>?)`, diskTimerHistoryLimit)
		return err
	}
	_, err := tx.Exec(`DELETE FROM disk_timer_observations WHERE machine_id=? AND receipt_seq NOT IN (SELECT receipt_seq FROM disk_timer_observations WHERE machine_id=? AND scope='user' ORDER BY receipt_seq DESC LIMIT ?) AND receipt_seq NOT IN (SELECT receipt_seq FROM disk_timer_observations WHERE machine_id=? AND scope='root' ORDER BY receipt_seq DESC LIMIT ?)`, machine, machine, diskTimerHistoryLimit, machine, diskTimerHistoryLimit)
	return err
}

func diskMatchingJobsTerminalTx(tx dbTx, machine, scope string) (bool, error) {
	rows, err := tx.Query(`SELECT j.state FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.machine_id=? AND d.resource_kind='script_v1' AND d.resource_id='disk-safe-clean-v2' AND json_extract(d.spec,'$.args.scope')=?`, machine, scope)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var state deploy.JobState
		if err = rows.Scan(&state); err != nil {
			return false, err
		}
		if !deploy.IsTerminal(state) {
			return false, nil
		}
	}
	return true, rows.Err()
}
func (s *Store) finishDiskRollbackTx(tx dbTx, machine, scope string, now time.Time) error {
	terminal, err := diskMatchingJobsTerminalTx(tx, machine, scope)
	if err != nil || !terminal {
		return err
	}
	result, err := tx.Exec(`UPDATE disk_ownership SET state='local-owned',revision=revision+1,changed_at=? WHERE machine_id=? AND scope=? AND state='rollback-pending'`, diskReceiptTime(now), machine, scope)
	if err != nil {
		return err
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		return nil
	}
	return s.recordAuditTx(tx, AuditEntry{At: now, MachineID: machine, Subject: scope, Action: "disk_ownership_rollback_complete", AuthSubject: "scheduler:disk-ownership", OK: true, Detail: "local-owned: all matching Hub cleanup jobs terminal"})
}
func (s *Store) ReconcileDiskOwnership(now time.Time) error {
	tx, err := s.beginWrite(context.Background(), "disk_ownership_reconcile")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT machine_id,scope FROM disk_ownership WHERE state='rollback-pending'`)
	if err != nil {
		return err
	}
	var targets [][2]string
	for rows.Next() {
		var target [2]string
		if err = rows.Scan(&target[0], &target[1]); err != nil {
			rows.Close()
			return err
		}
		targets = append(targets, target)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, t := range targets {
		if err = s.finishDiskRollbackTx(tx, t[0], t[1], now); err != nil {
			return err
		}
	}
	if err = pruneDiskTimersTx(tx, now, ""); err != nil {
		return err
	}
	return tx.Commit()
}
