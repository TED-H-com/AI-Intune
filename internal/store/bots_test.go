package store

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/channels"
	"path/filepath"
	"testing"
)

func TestChannelBotValidationAndAtomicAudit(t *testing.T) {
	s := newTestStore(t)
	if e := s.UpsertMachine(Machine{MachineID: "example-host", DisplayName: "Example", Expected: true}); e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	b := ChannelBot{Name: "example-bot", Kind: "discord", MachineID: "example-host", AgentType: "hermes", TokenRef: "env://BOT_TOKEN", Status: "unknown", Notes: "Example bot"}
	for _, change := range []func(*ChannelBot){
		func(b *ChannelBot) { b.Kind = "webhook" },
		func(b *ChannelBot) { b.AgentType = "invalid" },
		func(b *ChannelBot) { b.Status = "invalid" },
		func(b *ChannelBot) { b.TokenRef = "raw-secret" },
		func(b *ChannelBot) { b.MachineID = "missing" },
	} {
		invalid := b
		change(&invalid)
		if e := s.MutateChannelBot(ctx, "save", invalid, AuditEntry{}); e == nil {
			t.Fatal("accepted invalid bot")
		}
	}
	if e := s.MutateChannelBot(ctx, "save", b, AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	b.Kind = "telegram"
	b.AgentType = "openclaw"
	b.Status = "active"
	if e := s.MutateChannelBot(ctx, "save", b, AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	rows, e := s.ChannelBots()
	if e != nil || len(rows) != 1 || rows[0] != b {
		t.Fatal(rows, e)
	}
	entries, e := s.Audit("", 100)
	if e != nil {
		t.Fatal(e)
	}
	found := 0
	for _, a := range entries {
		if a.Action == AuditChannelManage && a.Subject == b.Name && a.Detail == "bot save" && a.OK {
			found++
		}
	}
	if found != 2 {
		t.Fatal("missing bot audit", found)
	}
	if _, e = s.DB().Exec("CREATE TRIGGER reject_bot_audit BEFORE INSERT ON audit_log WHEN NEW.action='channel-manage' BEGIN SELECT RAISE(ABORT,'unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	if e = s.MutateChannelBot(ctx, "remove", b, AuditEntry{}); e == nil {
		t.Fatal("unaudited delete")
	}
	rows, e = s.ChannelBots()
	if e != nil || len(rows) != 1 {
		t.Fatal("delete not rolled back")
	}
	if _, e = s.DB().Exec("DROP TRIGGER reject_bot_audit"); e != nil {
		t.Fatal(e)
	}
	if e = s.MutateChannelBot(ctx, "remove", b, AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	rows, e = s.ChannelBots()
	if e != nil || len(rows) != 0 {
		t.Fatal(rows, e)
	}
}

func TestChannelBotMigrationAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.UpsertMachine(Machine{MachineID: "example-host", DisplayName: "Example", Expected: true}); e != nil {
		t.Fatal(e)
	}
	c := channels.Config{ID: "example", Kind: "telegram", TokenRef: "env://BOT_TOKEN", ChatRef: "env://CHAT_ID"}
	if e = s.MutateChannel(context.Background(), "save", c, "", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e = s.MutateChannel(context.Background(), "bind", c, "example-host", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DB().Exec("DROP TABLE channel_bots"); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	b := ChannelBot{Name: "example-bot", Kind: "discord", MachineID: "example-host", AgentType: "other", TokenRef: "env://BOT_TOKEN", Status: "disabled"}
	if e = s.MutateChannelBot(context.Background(), "save", b, AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	bots, e := s.ChannelBots()
	if e != nil || len(bots) != 1 || bots[0] != b {
		t.Fatal(bots, e)
	}
	bindings, e := s.ChannelBindings()
	if e != nil || len(bindings) != 1 {
		t.Fatal(bindings, e)
	}
	configs, e := s.Channels()
	if e != nil || len(configs) != 1 || configs[0] != c {
		t.Fatal(configs, e)
	}
}
