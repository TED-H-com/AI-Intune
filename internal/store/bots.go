package store

import (
	"context"
	"errors"
	"github.com/teddashh/AI-Intune/internal/channels"
)

type ChannelBot struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	MachineID string `json:"machine_id"`
	AgentType string `json:"agent_type"`
	TokenRef  string `json:"token_ref"`
	Status    string `json:"status"`
	Notes     string `json:"notes"`
}

func (s *Store) ChannelBots() ([]ChannelBot, error) {
	rows, e := s.rdb.Query("SELECT name,kind,machine_id,agent_type,token_ref,status,notes FROM channel_bots ORDER BY name")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []ChannelBot{}
	for rows.Next() {
		var b ChannelBot
		if e = rows.Scan(&b.Name, &b.Kind, &b.MachineID, &b.AgentType, &b.TokenRef, &b.Status, &b.Notes); e != nil {
			return nil, e
		}
		out = append(out, b)
	}
	return out, rows.Err()
}
func (s *Store) MutateChannelBot(ctx context.Context, op string, b ChannelBot, a AuditEntry) error {
	if !channelIDPattern.MatchString(b.Name) {
		return errors.New("invalid bot name")
	}
	if op == "save" {
		if b.Kind != "discord" && b.Kind != "telegram" || b.AgentType != "hermes" && b.AgentType != "openclaw" && b.AgentType != "other" || b.Status != "active" && b.Status != "disabled" && b.Status != "unknown" || len(b.Notes) > 4096 {
			return errors.New("invalid bot metadata")
		}
		if e := channels.ValidateCredentialReference(b.TokenRef); e != nil {
			return e
		}
	}
	tx, e := s.beginWrite(ctx, "channel_bot_metadata")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	switch op {
	case "save":
		_, e = tx.Exec("INSERT INTO channel_bots(name,kind,machine_id,agent_type,token_ref,status,notes) VALUES(?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET kind=excluded.kind,machine_id=excluded.machine_id,agent_type=excluded.agent_type,token_ref=excluded.token_ref,status=excluded.status,notes=excluded.notes", b.Name, b.Kind, b.MachineID, b.AgentType, b.TokenRef, b.Status, b.Notes)
	case "remove":
		_, e = tx.Exec("DELETE FROM channel_bots WHERE name=?", b.Name)
	default:
		return errors.New("invalid bot operation")
	}
	if e != nil {
		return errors.New("bot metadata update failed")
	}
	a.Action = AuditChannelManage
	a.Subject = b.Name
	a.Detail = "bot " + op
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return e
	}
	return tx.Commit()
}
