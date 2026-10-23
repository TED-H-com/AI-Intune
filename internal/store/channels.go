package store

import (
	"context"
	"errors"
	"regexp"

	"github.com/teddashh/AI-Intune/internal/channels"
)

type ChannelBinding struct {
	ChannelID string `json:"channel_id"`
	MachineID string `json:"machine_id"`
}

var channelIDPattern = regexp.MustCompile("^[a-zA-Z0-9_-]{1,64}$")

func (s *Store) Channels() ([]channels.Config, error) {
	rows, e := s.rdb.Query("SELECT id,kind,token_ref,chat_ref,url_ref,secret_ref FROM outbound_channels ORDER BY id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []channels.Config{}
	for rows.Next() {
		var c channels.Config
		if e = rows.Scan(&c.ID, &c.Kind, &c.TokenRef, &c.ChatRef, &c.URLRef, &c.SecretRef); e != nil {
			return nil, e
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
func (s *Store) ChannelBindings() ([]ChannelBinding, error) {
	rows, e := s.rdb.Query("SELECT channel_id,machine_id FROM channel_bindings ORDER BY channel_id,machine_id")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ChannelBinding{}
	for rows.Next() {
		var b ChannelBinding
		if e = rows.Scan(&b.ChannelID, &b.MachineID); e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// MutateChannel commits metadata and its audit evidence atomically.
func (s *Store) MutateChannel(ctx context.Context, op string, c channels.Config, machine string, a AuditEntry) error {
	if !channelIDPattern.MatchString(c.ID) {
		return errors.New("invalid channel ID")
	}
	if op == "save" {
		if e := channels.ValidateConfig(c); e != nil {
			return e
		}
	}
	tx, e := s.beginWrite(ctx, "channel_metadata")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	switch op {
	case "save":
		_, e = tx.Exec("INSERT INTO outbound_channels(id,kind,token_ref,chat_ref,url_ref,secret_ref) VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind,token_ref=excluded.token_ref,chat_ref=excluded.chat_ref,url_ref=excluded.url_ref,secret_ref=excluded.secret_ref", c.ID, c.Kind, c.TokenRef, c.ChatRef, c.URLRef, c.SecretRef)
	case "remove":
		_, e = tx.Exec("DELETE FROM channel_bindings WHERE channel_id=?", c.ID)
		if e == nil {
			_, e = tx.Exec("DELETE FROM outbound_channels WHERE id=?", c.ID)
		}
	case "bind":
		_, e = tx.Exec("INSERT INTO channel_bindings(channel_id,machine_id) VALUES(?,?)", c.ID, machine)
	case "unbind":
		_, e = tx.Exec("DELETE FROM channel_bindings WHERE channel_id=? AND machine_id=?", c.ID, machine)
	default:
		return errors.New("invalid channel operation")
	}
	if e != nil {
		return errors.New("channel metadata update failed")
	}
	a.Action = AuditChannelManage
	a.Subject = c.ID
	a.Detail = op
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return e
	}
	return tx.Commit()
}

// InitializeChannels imports legacy reference configuration once. Deleting a
// channel in the UI must not cause it to reappear on the next Hub restart.
func (s *Store) InitializeChannels(ctx context.Context, configs []channels.Config) error {
	if len(configs) == 0 {
		return nil
	}
	tx, e := s.beginWrite(ctx, "initialize_channels")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	result, e := tx.Exec("INSERT OR IGNORE INTO channel_initialization(id) VALUES(1)")
	if e != nil {
		return e
	}
	n, e := result.RowsAffected()
	if e != nil {
		return e
	}
	if n == 0 {
		return tx.Commit()
	}
	for _, c := range configs {
		if e = channels.ValidateConfig(c); e != nil {
			return e
		}
		_, e = tx.Exec("INSERT OR IGNORE INTO outbound_channels(id,kind,token_ref,chat_ref,url_ref,secret_ref) VALUES(?,?,?,?,?,?)", c.ID, c.Kind, c.TokenRef, c.ChatRef, c.URLRef, c.SecretRef)
		if e != nil {
			return e
		}
	}
	return tx.Commit()
}
