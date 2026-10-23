package store

import (
	"context"
	"errors"
	"time"
)

type ChatUser struct {
	ChannelID string `json:"channel_id"`
	UserID    string `json:"user_id"`
	AccountID string `json:"account_id"`
}
type ChatApproval struct {
	ID, ChannelID, Destination, Requester, Target string
	Body                                          string `json:"-"`
	Expires                                       int64
}

func (s *Store) ChatUsers() ([]ChatUser, error) {
	rows, e := s.rdb.Query("SELECT channel_id,user_id,account_id FROM chat_allowlist ORDER BY channel_id,user_id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ChatUser{}
	for rows.Next() {
		var u ChatUser
		if e = rows.Scan(&u.ChannelID, &u.UserID, &u.AccountID); e != nil {
			return nil, e
		}
		out = append(out, u)
	}
	return out, rows.Err()
}
func (s *Store) MutateChatUser(ctx context.Context, u ChatUser, remove bool, a AuditEntry) error {
	if !channelIDPattern.MatchString(u.ChannelID) || len(u.UserID) == 0 || len(u.UserID) > 64 {
		return errors.New("invalid chat identity")
	}
	tx, e := s.beginWrite(ctx, "chat_allowlist")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if remove {
		_, e = tx.Exec("DELETE FROM chat_allowlist WHERE channel_id=? AND user_id=?", u.ChannelID, u.UserID)
	} else {
		_, e = tx.Exec("INSERT INTO chat_allowlist VALUES(?,?,?) ON CONFLICT(channel_id,user_id) DO UPDATE SET account_id=excluded.account_id", u.ChannelID, u.UserID, u.AccountID)
	}
	if e != nil {
		return e
	}
	a.Action = "chat-allowlist"
	a.Subject = u.ChannelID
	a.Detail = "identity mapping updated"
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return e
	}
	return tx.Commit()
}

// ClaimChatEvent fails closed at capacity rather than evicting live replay keys.
func (s *Store) ClaimChatEvent(ctx context.Context, channel, id string, now time.Time) (bool, error) {
	tx, e := s.beginWrite(ctx, "chat_event")
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("DELETE FROM chat_events WHERE expires<=?", now.Unix()); e != nil {
		return false, e
	}
	var n int
	if e = tx.QueryRow("SELECT COUNT(*) FROM chat_events").Scan(&n); e != nil {
		return false, e
	}
	if n >= 10000 {
		return false, nil
	}
	r, e := tx.Exec("INSERT OR IGNORE INTO chat_events VALUES(?,?,?)", channel, id, now.Add(24*time.Hour).Unix())
	if e != nil {
		return false, e
	}
	n64, e := r.RowsAffected()
	if e != nil {
		return false, e
	}
	return n64 == 1, tx.Commit()
}
func (s *Store) CreateChatApproval(ctx context.Context, p ChatApproval, a AuditEntry) error {
	tx, e := s.beginWrite(ctx, "chat_approval")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if _, e = tx.Exec("DELETE FROM chat_approvals WHERE expires<=?", time.Now().Unix()); e != nil {
		return e
	}
	var n int
	if e = tx.QueryRow("SELECT COUNT(*) FROM chat_approvals").Scan(&n); e != nil {
		return e
	}
	if n >= 1000 {
		return errors.New("approval capacity")
	}
	_, e = tx.Exec("INSERT INTO chat_approvals(id,channel_id,destination,requester,target,body,expires) VALUES(?,?,?,?,?,?,?)", p.ID, p.ChannelID, p.Destination, p.Requester, p.Target, p.Body, p.Expires)
	if e != nil {
		return e
	}
	a.Action = "chat-approval-request"
	a.Subject = p.ID
	a.Detail = "ack-alert requested"
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) PendingChatApprovals(now time.Time) ([]ChatApproval, error) {
	rows, e := s.rdb.Query("SELECT id,channel_id,destination,requester,target,body,expires FROM chat_approvals WHERE consumed=0 AND expires>? ORDER BY expires", now.Unix())
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ChatApproval{}
	for rows.Next() {
		var p ChatApproval
		if e = rows.Scan(&p.ID, &p.ChannelID, &p.Destination, &p.Requester, &p.Target, &p.Body, &p.Expires); e != nil {
			return nil, e
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ConsumeChatApproval commits one-time intent before invoking the canonical action.
func (s *Store) ConsumeChatApproval(ctx context.Context, id, channel, destination string, now time.Time, a AuditEntry, approve bool) (ChatApproval, error) {
	var p ChatApproval
	tx, e := s.beginWrite(ctx, "chat_approval_consume")
	if e != nil {
		return p, e
	}
	defer tx.Rollback()
	e = tx.QueryRow("SELECT id,channel_id,destination,requester,target,body,expires FROM chat_approvals WHERE id=? AND channel_id=? AND destination=? AND consumed=0 AND expires>?", id, channel, destination, now.Unix()).Scan(&p.ID, &p.ChannelID, &p.Destination, &p.Requester, &p.Target, &p.Body, &p.Expires)
	if e != nil {
		return p, e
	}
	if _, e = tx.Exec("UPDATE chat_approvals SET consumed=1 WHERE id=?", id); e != nil {
		return p, e
	}
	a.Action = "chat-approval-deny"
	if approve {
		a.Action = "chat-approval-approve"
	}
	a.Subject = id
	a.Detail = "one-time decision"
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return p, e
	}
	return p, tx.Commit()
}
