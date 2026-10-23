package store

import (
	"context"
	"database/sql"
	"errors"
	"github.com/teddashh/AI-Intune/internal/model"
	"time"
)

func (s *Store) SigninNotificationChannel() (string, error) {
	var id string
	e := s.rdb.QueryRow(`SELECT channel_id FROM signin_notification_setting WHERE id=1`).Scan(&id)
	if errors.Is(e, sql.ErrNoRows) {
		return "", nil
	}
	return id, e
}
func (s *Store) SetSigninNotificationChannel(ctx context.Context, id string, a AuditEntry) error {
	tx, e := s.beginWrite(ctx, "signin_notification_setting")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if id != "" {
		var n int
		if e = tx.QueryRow(`SELECT count(*) FROM outbound_channels WHERE id=?`, id).Scan(&n); e != nil {
			return e
		}
		if n != 1 {
			return ErrNotFound
		}
	}
	if _, e = tx.Exec(`INSERT INTO signin_notification_setting(id,channel_id) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET channel_id=excluded.channel_id`, id); e != nil {
		return e
	}
	a.At = s.now()
	a.Action = AuditSigninNotifications
	a.Subject = "Sign-ins"
	a.Detail = "notification preference changed"
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) signinNotificationFacts(tx dbTx, machine string, health []model.AuthHealth, now time.Time) error {
	var channel string
	_ = tx.QueryRow(`SELECT channel_id FROM signin_notification_setting WHERE id=1`).Scan(&channel)
	for _, h := range health {
		var old, last string
		_ = tx.QueryRow(`SELECT status,last_notified_at FROM signin_notification_state WHERE machine_id=? AND cli=? AND slot=?`, machine, h.CLI, h.Slot).Scan(&old, &last)
		pending := 0
		at, _ := time.Parse(time.RFC3339Nano, last)
		if channel != "" && (old == "ok" || old == "expiring") && h.Status == "logged_out" && (at.IsZero() || now.Sub(at) >= 12*time.Hour) {
			pending = 1
		}
		_, e := tx.Exec(`INSERT INTO signin_notification_state(machine_id,cli,slot,status,account,pending) VALUES(?,?,?,?,?,?) ON CONFLICT(machine_id,cli,slot) DO UPDATE SET status=excluded.status,account=excluded.account,pending=CASE WHEN excluded.status!='logged_out' THEN 0 ELSE MAX(signin_notification_state.pending,excluded.pending) END`, machine, h.CLI, h.Slot, h.Status, h.Account, pending)
		if e != nil {
			return e
		}
	}
	return nil
}

type SigninNotification struct {
	MachineID, DisplayName, CLI, Account string
	Slot                                 int
}

// ClaimSigninNotifications reserves the 12-hour dedupe window before sending.
// A crash or uncertain delivery is never automatically retried.
func (s *Store) ClaimSigninNotifications() ([]SigninNotification, error) {
	tx, e := s.beginWrite(context.Background(), "signin_notification_claim")
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	rows, e := tx.Query(`SELECT n.machine_id,m.display_name,n.cli,n.slot,n.account FROM signin_notification_state n JOIN machine_registry m ON n.machine_id=m.machine_id WHERE n.pending=1 AND m.retired_at IS NULL LIMIT 100`)
	if e != nil {
		return nil, e
	}
	out := []SigninNotification{}
	for rows.Next() {
		var n SigninNotification
		if e = rows.Scan(&n.MachineID, &n.DisplayName, &n.CLI, &n.Slot, &n.Account); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, n)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, n := range out {
		if _, e = tx.Exec(`UPDATE signin_notification_state SET pending=0,last_notified_at=? WHERE machine_id=? AND cli=? AND slot=?`, fmtTime(s.now()), n.MachineID, n.CLI, n.Slot); e != nil {
			return nil, e
		}
		if e = s.recordAuditTx(tx, AuditEntry{At: s.now(), Action: AuditChannelTest, MachineID: n.MachineID, Subject: "Sign-ins", Detail: "sign-in notification requested", OK: true}); e != nil {
			return nil, e
		}
	}
	return out, tx.Commit()
}

// RecordSigninNotificationResult owns the closed-vocabulary delivery audit.
func (s *Store) RecordSigninNotificationResult(machine, provider string, ok bool) error {
	return s.RecordAudit(AuditEntry{At: s.now(), Action: AuditChannelTest, MachineID: machine, Subject: provider, Detail: "sign-in notification completed", OK: ok})
}
