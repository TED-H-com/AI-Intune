package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/state"
)

const DefaultOfflineAlertMinutes = 10
const OfflineRecoveryHold = 2 * time.Minute
const offlineSettingsOperation = "offline-alert-settings:v1"
const AuditOfflineAlertSettings AuditAction = "offline-alert-settings"

type OfflineAlertSettings struct {
	Minutes  int   `json:"minutes"`
	Revision int64 `json:"revision"`
}
type OfflineAlertSettingsPreview struct {
	Current       OfflineAlertSettings `json:"current"`
	Minutes       int                  `json:"minutes"`
	PreviewDigest string               `json:"preview_digest"`
}
type OfflineAlertSettingsRequest struct {
	Minutes          int    `json:"minutes"`
	ExpectedRevision *int64 `json:"expected_revision"`
	PreviewDigest    string `json:"preview_digest"`
	Reason           string `json:"reason"`
	Confirm          string `json:"confirm"`
}
type OfflineAlertSettingsResult struct {
	Settings OfflineAlertSettings `json:"settings"`
	Replayed bool                 `json:"replayed"`
}

func ValidOfflineAlertMinutes(n int) bool { return n >= 1 && n <= 1440 }

func readOfflineAlertSettings(db interface{ QueryRow(string, ...any) *sql.Row }) (OfflineAlertSettings, error) {
	out := OfflineAlertSettings{Minutes: DefaultOfflineAlertMinutes}
	err := db.QueryRow(`SELECT minutes,revision FROM offline_alert_settings WHERE id=1`).Scan(&out.Minutes, &out.Revision)
	if errors.Is(err, sql.ErrNoRows) {
		return out, nil
	}
	if err == nil && (!ValidOfflineAlertMinutes(out.Minutes) || out.Revision < 0) {
		err = errors.New("invalid offline alert settings")
	}
	return out, err
}
func (s *Store) OfflineAlertSettings() (OfflineAlertSettings, error) {
	return readOfflineAlertSettings(s.rdb)
}
func offlineSettingsDigest(current OfflineAlertSettings, minutes int) string {
	return digestOf(fmt.Sprintf("offline-alert-settings:v1:%d:%d:%d", current.Revision, current.Minutes, minutes))
}
func (s *Store) PreviewOfflineAlertSettings(minutes int) (OfflineAlertSettingsPreview, error) {
	if !ValidOfflineAlertMinutes(minutes) {
		return OfflineAlertSettingsPreview{}, operatorError("OFFLINE_ALERT_INVALID", "minutes must be 1..1440")
	}
	current, err := s.OfflineAlertSettings()
	return OfflineAlertSettingsPreview{Current: current, Minutes: minutes, PreviewDigest: offlineSettingsDigest(current, minutes)}, err
}
func (s *Store) ApplyOfflineAlertSettings(req OfflineAlertSettingsRequest, key string, audit AuditEntry) (OfflineAlertSettingsResult, error) {
	var out OfflineAlertSettingsResult
	reason, err := boundedtext.Reason(req.Reason)
	if err != nil {
		return out, operatorError(OperatorCodeReasonRequired, err.Error())
	}
	req.Reason = reason
	if strings.TrimSpace(key) == "" || len(key) > 200 {
		return out, operatorError(OperatorCodeIdempotencyKeyRequired, "Idempotency-Key required (max 200 bytes)")
	}
	raw, _ := json.Marshal(req)
	digest := digestOf(string(raw))
	audit.Action = AuditOfflineAlertSettings
	audit.Subject = "offline-alerts"
	audit.Reason = reason
	audit.IdempotencyKey = key
	audit.RequestDigest = digest
	tx, err := s.beginWrite(context.Background(), "offline_alert_settings")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	replay, rejected, err := s.policyIdempotency(tx, key, offlineSettingsOperation, digest, &audit, func(raw string) (any, error) {
		var r OfflineAlertSettingsResult
		e := json.Unmarshal([]byte(raw), &r)
		if e == nil && (!ValidOfflineAlertMinutes(r.Settings.Minutes) || r.Settings.Revision < 0) {
			e = errors.New("invalid cached offline settings")
		}
		r.Replayed = true
		return r, e
	}, "offline alert settings unchanged")
	if err != nil {
		return out, err
	}
	if rejected != nil {
		return out, rejected
	}
	if replay != nil {
		return replay.(OfflineAlertSettingsResult), nil
	}
	reject := func(code, detail string) (OfflineAlertSettingsResult, error) {
		return out, s.policyReject(tx, key, offlineSettingsOperation, digest, &audit, code, detail)
	}
	if !ValidOfflineAlertMinutes(req.Minutes) {
		return reject("OFFLINE_ALERT_INVALID", "minutes must be 1..1440")
	}
	if req.Confirm != "OFFLINE ALERTS" {
		return reject(OperatorCodeConfirmationMismatch, "type OFFLINE ALERTS to confirm")
	}
	if req.ExpectedRevision == nil {
		return reject(OperatorCodePreconditionRequired, "expected_revision required")
	}
	current, err := readOfflineAlertSettings(tx)
	if err != nil {
		return out, err
	}
	if *req.ExpectedRevision != current.Revision {
		return reject(OperatorCodeSettingPolicyConflict, "offline alert settings changed; preview again")
	}
	if req.PreviewDigest != offlineSettingsDigest(current, req.Minutes) {
		return reject(OperatorCodePreviewStale, "offline alert preview changed; preview again")
	}
	next := current
	if next.Minutes != req.Minutes {
		if next.Revision == math.MaxInt64 {
			return reject(OperatorCodeSettingPolicyConflict, "offline alert revision exhausted")
		}
		next.Minutes = req.Minutes
		next.Revision++
		if _, err = tx.Exec(`INSERT INTO offline_alert_settings(id,minutes,revision) VALUES(1,?,?) ON CONFLICT(id) DO UPDATE SET minutes=excluded.minutes,revision=excluded.revision`, next.Minutes, next.Revision); err != nil {
			return out, err
		}
	}
	out.Settings = next
	return out, s.policyCommit(tx, key, offlineSettingsOperation, digest, &audit, out)
}

// OfflineAlertSend is a fenced, expiring reservation. Network I/O is outside
// the writer transaction; successful delivery is latched independently of the
// prunable notifications ledger, so retention cannot resend a long outage.
type OfflineAlertSend struct {
	MachineID, EpisodeID, Token, Kind string
	Recovery                          bool
	CheckinDeadline                   time.Time
}

// ClaimOfflineAlerts uses the same derived facts/deadline as the machine page.
// The writer rechecks lifecycle and exact Hub check-in receipt before using
// each read. Monitor-only machines are deliberately not filtered by jobs flags.
func (s *Store) ClaimOfflineAlerts(now time.Time) ([]OfflineAlertSend, error) {
	ov, err := s.Overview(now)
	if err != nil {
		return nil, err
	}
	out := []OfflineAlertSend{}
	for _, m := range ov.Machines {
		send, err := s.claimOfflineAlert(m, now.UTC())
		if err != nil {
			return nil, err
		}
		if send != nil {
			out = append(out, *send)
			if len(out) == 100 {
				break
			}
		}
	}
	return out, nil
}
func (s *Store) claimOfflineAlert(m MachineRow, now time.Time) (*OfflineAlertSend, error) {
	tx, err := s.beginWrite(context.Background(), "offline_alert_claim")
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var retired sql.NullString
	var revision int64
	if err = tx.QueryRow(`SELECT retired_at,lifecycle_revision FROM machine_registry WHERE machine_id=?`, m.MachineID).Scan(&retired, &revision); err != nil {
		return nil, err
	}
	if retired.Valid {
		_, err = tx.Exec(`DELETE FROM machine_offline_alerts WHERE machine_id=?`, m.MachineID)
		if err != nil {
			return nil, err
		}
		return nil, tx.Commit()
	}
	var latest sql.NullString
	if err = tx.QueryRow(`SELECT MAX(received_at) FROM machine_checkins WHERE machine_id=?`, m.MachineID).Scan(&latest); err != nil {
		return nil, err
	}
	if !latest.Valid || !parseTime(latest.String).Equal(m.Facts.LastCheckinReceived) {
		return nil, nil
	}
	settings, err := readOfflineAlertSettings(tx)
	if err != nil {
		return nil, err
	}
	var episode, since, recovery, receipt, attempt, lease, token string
	var sent, failures int
	var lifecycle int64
	err = tx.QueryRow(`SELECT episode_id,unreachable_since,recovery_since,last_checkin_at,offline_sent,last_attempt_at,failures,lease_until,lease_token,lifecycle_revision FROM machine_offline_alerts WHERE machine_id=?`, m.MachineID).Scan(&episode, &since, &recovery, &receipt, &sent, &attempt, &failures, &lease, &token, &lifecycle)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	if lifecycle != revision {
		episode = ""
		sent = 0
		recovery = ""
		attempt = ""
		lease = ""
		failures = 0
	}
	unreachable := m.State == state.Unreachable
	reporting := m.Facts.EverCheckedIn && !now.After(state.CheckinDeadline(m.Facts))
	if !unreachable && !reporting { // identity conflict / unknown is not recovery.
		if episode != "" {
			_, err = tx.Exec(`UPDATE machine_offline_alerts SET recovery_since='' WHERE machine_id=?`, m.MachineID)
		}
		if err != nil {
			return nil, err
		}
		return nil, tx.Commit()
	}
	if unreachable {
		// A successful heartbeat breaks an unnotified outage even between sweeps.
		if episode == "" || sent == 0 && receipt != latest.String {
			episode = newID()
			since = fmtTime(state.CheckinDeadline(m.Facts))
			sent = 0
			attempt = ""
			failures = 0
			lease = ""
		}
		recovery = ""
	} else {
		if episode == "" || sent == 0 {
			_, err = tx.Exec(`DELETE FROM machine_offline_alerts WHERE machine_id=?`, m.MachineID)
			if err != nil {
				return nil, err
			}
			return nil, tx.Commit()
		}
		previous := m.Facts
		previous.LastCheckinReceived = parseTime(receipt)
		if recovery == "" || m.Facts.LastCheckinReceived.After(state.CheckinDeadline(previous)) {
			// A gap while the sweep was stopped also breaks the stable hold.
			recovery = fmtTime(m.Facts.LastCheckinReceived)
			attempt = ""
			failures = 0
			lease = ""
		}
	}
	_, err = tx.Exec(`INSERT INTO machine_offline_alerts(machine_id,episode_id,unreachable_since,recovery_since,last_checkin_at,offline_sent,last_attempt_at,failures,lease_until,lease_token,lifecycle_revision) VALUES(?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(machine_id) DO UPDATE SET episode_id=excluded.episode_id,unreachable_since=excluded.unreachable_since,recovery_since=excluded.recovery_since,last_checkin_at=excluded.last_checkin_at,offline_sent=excluded.offline_sent,last_attempt_at=excluded.last_attempt_at,failures=excluded.failures,lease_until=excluded.lease_until,lease_token=excluded.lease_token,lifecycle_revision=excluded.lifecycle_revision`, m.MachineID, episode, since, recovery, latest.String, sent, attempt, failures, lease, token, revision)
	if err != nil {
		return nil, err
	}
	due := unreachable && sent == 0 && now.After(parseTime(since).Add(time.Duration(settings.Minutes)*time.Minute)) || !unreachable && sent == 1 && !now.Before(parseTime(recovery).Add(OfflineRecoveryHold))
	if !due || lease != "" && now.Before(parseTime(lease)) || attempt != "" && now.Before(parseTime(attempt).Add(offlineAlertBackoff(failures))) {
		return nil, tx.Commit()
	}
	token = newID()
	_, err = tx.Exec(`UPDATE machine_offline_alerts SET lease_token=?,lease_until=?,last_attempt_at=? WHERE machine_id=?`, token, fmtTime(now.Add(2*time.Minute)), fmtTime(now), m.MachineID)
	if err != nil {
		return nil, err
	}
	if err = tx.Commit(); err != nil {
		return nil, err
	}
	kind := "machine-offline:" + episode
	if !unreachable {
		kind += ":recovery"
	}
	return &OfflineAlertSend{MachineID: m.MachineID, EpisodeID: episode, Token: token, Kind: kind, Recovery: !unreachable, CheckinDeadline: state.CheckinDeadline(m.Facts)}, nil
}
func offlineAlertBackoff(failures int) time.Duration {
	if failures <= 1 {
		return time.Minute
	}
	if failures >= 7 {
		return time.Hour
	}
	return time.Minute << uint(failures-1)
}
func (s *Store) FinishOfflineAlert(send OfflineAlertSend, delivered bool) error {
	tx, err := s.beginWrite(context.Background(), "offline_alert_finish")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if delivered && send.Recovery {
		_, err = tx.Exec(`DELETE FROM machine_offline_alerts WHERE machine_id=? AND episode_id=? AND lease_token=?`, send.MachineID, send.EpisodeID, send.Token)
	} else if delivered {
		_, err = tx.Exec(`UPDATE machine_offline_alerts SET offline_sent=1,failures=0,lease_until='',lease_token='' WHERE machine_id=? AND episode_id=? AND lease_token=?`, send.MachineID, send.EpisodeID, send.Token)
	} else {
		_, err = tx.Exec(`UPDATE machine_offline_alerts SET failures=MIN(failures+1,7),lease_until='',lease_token='' WHERE machine_id=? AND episode_id=? AND lease_token=?`, send.MachineID, send.EpisodeID, send.Token)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}

// OfflineAlertEligible rechecks the reservation immediately before external I/O.
// Retirement, lifecycle changes or a new receipt invalidate stale sends.
func (s *Store) OfflineAlertEligible(send OfflineAlertSend, now time.Time) (bool, error) {
	var since string
	var minutes int
	err := s.rdb.QueryRow(`SELECT a.unreachable_since,COALESCE((SELECT minutes FROM offline_alert_settings WHERE id=1),10) FROM machine_offline_alerts a JOIN machine_registry m ON a.machine_id=m.machine_id WHERE a.machine_id=? AND a.episode_id=? AND a.lease_token=? AND a.lease_until>? AND m.retired_at IS NULL AND a.lifecycle_revision=m.lifecycle_revision AND a.last_checkin_at=(SELECT MAX(received_at) FROM machine_checkins WHERE machine_id=a.machine_id)`, send.MachineID, send.EpisodeID, send.Token, fmtTime(now)).Scan(&since, &minutes)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if send.Recovery {
		return !now.After(send.CheckinDeadline), nil
	}
	return ValidOfflineAlertMinutes(minutes) && now.After(parseTime(since).Add(time.Duration(minutes)*time.Minute)), nil
}
