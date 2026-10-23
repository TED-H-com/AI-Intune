package store

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signinFixture(t *testing.T) (*Store, string) {
	t.Helper()
	s := newTestStore(t)
	id := mustEnroll(t, s, "Example host", time.Now().UTC())
	if _, e := s.DB().Exec(`UPDATE machine_registry SET os='linux' WHERE machine_id=?`, id); e != nil {
		t.Fatal(e)
	}
	return s, id
}
func TestSigninLifecycleAndCodeNeverPersisted(t *testing.T) {
	s, m := signinFixture(t)
	ctx := context.Background()
	v, e := s.StartSignin(ctx, m, "agy", 2, AuditEntry{})
	if e != nil {
		t.Fatal(e)
	}
	if _, e = s.StartSignin(ctx, m, "agy", 2, AuditEntry{}); e == nil {
		t.Fatal("duplicate active sign-in")
	}
	commands := s.SigninCommands(m)
	if len(commands) != 1 || commands[0].Operation != "start" {
		t.Fatalf("commands %#v", commands)
	}
	if len(s.SigninCommands(m)) != 0 {
		t.Fatal("start delivered twice")
	}
	if e = s.UpdateSignin("foreign", model.SigninUpdate{ID: v.ID, State: "done"}); e == nil {
		t.Fatal("cross-machine update accepted")
	}
	if e = s.UpdateSignin(m, model.SigninUpdate{ID: v.ID, State: "waiting_for_code", URL: "https://evil.example/secret"}); e != nil {
		t.Fatal(e)
	}
	if s.SigninDisplay(v.ID).URL != "" {
		t.Fatal("untrusted URL")
	}
	code := "synthetic-ONE-use-code-87241"
	if e = s.SigninAction(ctx, v.ID, "code", code, AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e = s.SigninAction(ctx, v.ID, "code", code, AuditEntry{}); e == nil {
		t.Fatal("code submitted twice")
	}
	commands = s.SigninCommands(m)
	if len(commands) != 1 || commands[0].Code != code {
		t.Fatal("code not delivered")
	}
	if len(s.SigninCommands(m)) != 0 {
		t.Fatal("code delivered twice")
	}
	// Search every textual database column, including audit, and SQLite/WAL files.
	rows, e := s.DB().Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if e != nil {
		t.Fatal(e)
	}
	var tables []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		tables = append(tables, n)
	}
	rows.Close()
	for _, table := range tables {
		rows, e := s.DB().Query(`SELECT * FROM "` + table + `"`)
		if e != nil {
			t.Fatal(e)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptr := make([]any, len(cols))
			for i := range vals {
				ptr[i] = &vals[i]
			}
			if e = rows.Scan(ptr...); e != nil {
				t.Fatal(e)
			}
			for _, val := range vals {
				if text, ok := val.(string); ok && strings.Contains(text, code) {
					t.Fatalf("code persisted in %s", table)
				}
			}
		}
		rows.Close()
	}
	var dbpath string
	var seq int
	var name string
	if e = s.DB().QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &dbpath); e != nil {
		t.Fatal(e)
	}
	paths, _ := filepath.Glob(dbpath + "*")
	for _, path := range paths {
		b, _ := os.ReadFile(path)
		if strings.Contains(string(b), code) {
			t.Fatalf("code written to %s", filepath.Base(path))
		}
	}
	if e = s.SigninAction(ctx, v.ID, "cancel", "", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e = s.UpdateSignin(m, model.SigninUpdate{ID: v.ID, State: "done"}); e == nil {
		t.Fatal("cancelled session revived")
	}
	if _, e = s.StartSignin(ctx, m, "agy", 2, AuditEntry{}); e != nil {
		t.Fatal(e)
	}
}
func TestSigninExpiryAndAtomicAudit(t *testing.T) {
	s, m := signinFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.nowFn = func() time.Time { return now }
	v, e := s.StartSignin(context.Background(), m, "codex", 1, AuditEntry{})
	if e != nil {
		t.Fatal(e)
	}
	now = now.Add(16 * time.Minute)
	if e = s.ExpireSignins(); e != nil {
		t.Fatal(e)
	}
	var state string
	_ = s.DB().QueryRow(`SELECT state FROM signin_sessions WHERE id=?`, v.ID).Scan(&state)
	if state != "expired" {
		t.Fatal(state)
	}
	var count int
	_ = s.DB().QueryRow(`SELECT count(*) FROM audit_log WHERE action='signin_result' AND subject=?`, v.ID).Scan(&count)
	if count != 1 {
		t.Fatal(count)
	}
	if _, e = s.DB().Exec(`CREATE TRIGGER fail_signin_audit BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'fixture'); END`); e != nil {
		t.Fatal(e)
	}
	if _, e = s.StartSignin(context.Background(), m, "grok", 1, AuditEntry{}); e == nil {
		t.Fatal("audit failure accepted")
	}
	_ = s.DB().QueryRow(`SELECT count(*) FROM signin_sessions WHERE cli='grok'`).Scan(&count)
	if count != 0 {
		t.Fatal("unaudited session persisted")
	}
}
func TestSigninsGroupAccountsAcrossHosts(t *testing.T) {
	s, m := signinFixture(t)
	other := mustEnroll(t, s, "Another host", time.Now().UTC())
	now := time.Now().UTC()
	for _, id := range []string{m, other} {
		if e := s.RecordSigninHealth(id, []model.AuthHealth{{CLI: "agy", Slot: 1, Account: "person@example.com", Status: "logged_out"}, {CLI: "agy", Slot: 2, Status: "ok"}}, now); e != nil {
			t.Fatal(e)
		}
	}
	groups, e := s.Signins()
	if e != nil {
		t.Fatal(e)
	}
	if len(groups) != 2 {
		t.Fatal(groups)
	}
	for _, g := range groups {
		if len(g.Hosts) != 2 {
			t.Fatal(g)
		}
		if g.Account != "" && g.Needs != 2 {
			t.Fatal(g)
		}
	}
}
func TestSigninNotificationDedupe(t *testing.T) {
	s, m := signinFixture(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.nowFn = func() time.Time { return now }
	if e := s.MutateChannel(context.Background(), "save", testSigninChannel(), "", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	update := func(status string) {
		t.Helper()
		if e := s.RecordSigninHealth(m, []model.AuthHealth{{CLI: "codex", Slot: 1, Status: status}}, now); e != nil {
			t.Fatal(e)
		}
	}
	update("ok")
	update("logged_out")
	v, e := s.ClaimSigninNotifications()
	if e != nil || len(v) != 0 {
		t.Fatal("default enabled", e, v)
	}
	if e = s.SetSigninNotificationChannel(context.Background(), "example", AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	update("ok")
	update("logged_out")
	v, e = s.ClaimSigninNotifications()
	if e != nil || len(v) != 1 {
		t.Fatal(e, v)
	}
	update("ok")
	update("logged_out")
	v, e = s.ClaimSigninNotifications()
	if e != nil || len(v) != 0 {
		t.Fatal("dedupe", e, v)
	}
	now = now.Add(13 * time.Hour)
	update("expiring")
	update("logged_out")
	v, e = s.ClaimSigninNotifications()
	if e != nil || len(v) != 1 {
		t.Fatal(e, v)
	}
}

func testSigninChannel() channels.Config {
	return channels.Config{ID: "example", Kind: "webhook", URLRef: "env://EXAMPLE_WEBHOOK", SecretRef: "env://EXAMPLE_SECRET"}
}
