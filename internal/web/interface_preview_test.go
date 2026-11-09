package web

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/tailnet"
)

// TestInterfacePreview exports real server-rendered pages for local browser review.
// It uses an isolated store and never connects to a running Hub.
func TestInterfacePreview(t *testing.T) {
	dir := os.Getenv("CLAWCTL_INTERFACE_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set CLAWCTL_INTERFACE_PREVIEW_DIR to export interface fixtures")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	s, st := newServer(t)
	s.SetTailnetStatus(tailnet.Status{Available: true, Peers: []tailnet.Peer{{Hostname: "review-candidate", StableID: "review-peer", IP: "100.64.0.2", Online: true}}})
	id := onlineMachine(t, st, "design-review-device")
	pages := map[string]string{
		"dashboard": "/", "devices": "/machines", "device": "/machines/" + id,
		"apps": "/apps", "reports": "/reports", "enrollment": "/machines/enrollment",
		"jobs": "/jobs", "deployments": "/deployments", "maintenance": "/tenant/maintenance",
		"readiness": "/readiness", "signins": "/signins", "channels": "/channels",
		"schedules": "/tenant/schedules", "audit": "/audit", "configuration": "/machines/configuration",
		"compliance": "/machines/compliance", "diagnostics": "/machines/diagnostics",
		"schedule-form": "/tenant/schedules/new", "software": "/reports/software", "install": "/reports/install",
		"profile": "/reports/profile", "changes": "/reports/changes", "tickets": "/reports/tickets",
		"disk-alerts": "/tenant/disk-alerts", "disk-policies": "/tenant/disk-policies", "approvals": "/tenant/approvals",
		"certificates": "/tenant/certificates", "tailnet": "/settings/tailnet", "loops": "/attention/loops",
		"secrets": "/secrets", "updates": "/updates", "lifecycle": "/machines/lifecycle",
	}
	for name, path := range pages {
		t.Run(name, func(t *testing.T) {
			body := get(t, s, path)
			if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0600); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, setup := range []bool{false, true} {
		name := "login"
		if setup {
			name = "setup"
		}
		rec := httptest.NewRecorder()
		s.RenderAccountForm(rec, setup, "/", "")
		if err := os.WriteFile(filepath.Join(dir, name+".html"), rec.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestInterfacePopulatedPreview exercises layouts hidden by empty-state fixtures.
func TestInterfacePopulatedPreview(t *testing.T) {
	dir := os.Getenv("CLAWCTL_INTERFACE_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set CLAWCTL_INTERFACE_PREVIEW_DIR to export populated fixtures")
	}
	s, st := newServer(t)
	s.SetTailnetStatus(tailnet.Status{Available: true})
	id := onlineMachine(t, st, "engineering-workstation-with-a-long-display-name")
	now := time.Now().UTC()
	if err := st.RecordSigninHealth(id, []model.AuthHealth{
		{CLI: "agy", Slot: 1, Account: "engineering-operations@example.com", Status: "logged_out"},
		{CLI: "codex", Slot: 1, Account: "engineering-operations@example.com", Status: "ok"},
	}, now); err != nil {
		t.Fatal(err)
	}
	session, err := st.StartSignin(context.Background(), id, "agy", 1, store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	st.SigninCommands(id)
	if err = st.UpdateSignin(id, model.SigninUpdate{ID: session.ID, State: "waiting_for_code", URL: "https://accounts.google.com/o/oauth2/auth?fixture=1"}); err != nil {
		t.Fatal(err)
	}
	for _, admin := range []bool{false, true} {
		role := "viewer"
		if admin {
			role = "admin"
		}
		req := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/signins", nil), diskWebPrincipal(admin, true, "fixture"))
		rec := httptest.NewRecorder()
		s.signinsPage(rec, req)
		exportInterfaceFixture(t, dir, "signins-"+role, rec)
		rec = httptest.NewRecorder()
		req = operatorauth.WithPrincipal(httptest.NewRequest("GET", "/channels", nil), diskWebPrincipal(admin, true, "fixture"))
		s.render(rec, req, "channels.html", page{Title: "Channels", Nav: "channels", Channels: &channelsView{
			Rows:      []channelRow{{ID: "operations-alerts", Kind: "webhook", Status: "ready"}},
			Bindings:  []store.ChannelBinding{{ChannelID: "operations-alerts", MachineID: id}},
			Bots:      []store.ChannelBot{{Name: "operations-bot", Kind: "discord", MachineID: id, AgentType: "hermes", TokenRef: "env://REVIEW_BOT", Status: "active"}},
			Allowlist: []store.ChatUser{{ChannelID: "operations-alerts", UserID: "review-user", AccountID: "review-operator"}},
		}})
		exportInterfaceFixture(t, dir, "channels-"+role, rec)
	}
	rec := httptest.NewRecorder()
	req := verifiedWebRequest(httptest.NewRequest("GET", "/machines/enrollment", nil), "example.com/cap/clawctl-admin")
	s.render(rec, req, "enrollment_preview.html", page{Title: "確認註冊", Nav: "machines-enrollment", EnrollPreview: &enrollPreviewResult{
		Name: "engineering-workstation-with-a-long-display-name", Reason: "納管工程團隊工作站，套用已核准的應用程式設定與監控。", TTL: "2 小時", ExpiresAt: "2026-11-08 16:00", CreatesExpectedMachine: true, RevocationKeepsRegistryRow: true,
	}})
	exportInterfaceFixture(t, dir, "enrollment-review", rec)
}

func exportInterfaceFixture(t *testing.T, dir, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "</html>") {
		t.Fatalf("incomplete fixture %s (status %d)", name, rec.Code)
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".html"), rec.Body.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
}
