package store

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/channels"
	"testing"
)

func TestChannelMetadataAtomicAuditAndInitialization(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	c := channels.Config{ID: "example", Kind: "telegram", TokenRef: "env://TELEGRAM_BOT_TOKEN", ChatRef: "env://TELEGRAM_CHAT_ID"}
	if e := st.InitializeChannels(ctx, []channels.Config{c}); e != nil {
		t.Fatal(e)
	}
	if e := st.MutateChannel(ctx, "remove", c, "", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e := st.InitializeChannels(ctx, []channels.Config{c}); e != nil {
		t.Fatal(e)
	}
	rows, e := st.Channels()
	if e != nil || len(rows) != 0 {
		t.Fatal("removed channel reimported", rows, e)
	}
	if e := st.MutateChannel(ctx, "save", c, "", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e := st.UpsertMachine(Machine{MachineID: "machine-example", DisplayName: "Example", Expected: true}); e != nil {
		t.Fatal(e)
	}
	if e := st.MutateChannel(ctx, "bind", c, "missing-machine", AuditEntry{}); e == nil {
		t.Fatal("binding accepted unknown machine")
	}
	if e := st.MutateChannel(ctx, "bind", c, "machine-example", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	bindings, e := st.ChannelBindings()
	if e != nil || len(bindings) != 1 {
		t.Fatal(bindings, e)
	}
	// Audit failure must roll back both the channel deletion and binding deletion.
	if _, e := st.db.Exec("CREATE TRIGGER reject_channel_audit BEFORE INSERT ON audit_log WHEN NEW.action='channel-manage' BEGIN SELECT RAISE(ABORT,'audit unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	if e := st.MutateChannel(ctx, "remove", c, "", AuditEntry{}); e == nil {
		t.Fatal("accepted unaudited mutation")
	}
	rows, e = st.Channels()
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	bindings, e = st.ChannelBindings()
	if e != nil || len(bindings) != 1 {
		t.Fatal(bindings, e)
	}
	c.TokenRef = "raw-secret-value"
	if e := st.MutateChannel(ctx, "save", c, "", AuditEntry{}); e == nil {
		t.Fatal("stored raw credential")
	}
}
