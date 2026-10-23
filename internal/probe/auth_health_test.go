package probe

import (
	"context"
	"errors"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAuthHealthFixtures(t *testing.T) {
	home := t.TempDir()
	now := time.Now().UTC()
	write := func(path, body string) {
		t.Helper()
		path = filepath.Join(home, path)
		if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
			t.Fatal(e)
		}
		if e := os.WriteFile(path, []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
		if e := os.Chmod(path, 0600); e != nil {
			t.Fatal(e)
		}
	}
	write(".gemini/antigravity-cli/antigravity-oauth-token", `{"email":"one@example.com","token":{"refresh_token":"synthetic"}}`)
	write(".gemini/antigravity-accounts/acct2-home/.gemini/antigravity-cli/antigravity-oauth-token", `{"email":"two@example.com","token":{"expiry":"2000-01-01T00:00:00Z"}}`)
	write(".gemini/antigravity-accounts/acct8-home/.gemini/antigravity-cli/antigravity-oauth-token", `{malformed`)
	write(".gemini/antigravity-accounts/acct9-home/.gemini/antigravity-cli/antigravity-oauth-token", `{}`)
	write(".config/claude-automation/oauth-token", "sk-ant-oat"+strings.Repeat("Synthetic_", 10))
	write(".grok/auth.json", `{"https://auth.x.ai::fixture":{"expires_at":"`+now.Add(12*time.Hour).Format(time.RFC3339)+`"}}`)
	facts := authHealth(context.Background(), home, now, func(context.Context, string) (string, error) {
		return "✓ Logged in to github.com account example-user (keyring)", nil
	})
	found := map[string]model.AuthHealth{}
	for _, h := range facts {
		key := h.CLI + string(rune('0'+h.Slot))
		found[key] = h
		if strings.Contains(h.Reason, "synthetic") {
			t.Fatal("secret in reason")
		}
	}
	for key, status := range map[string]string{"agy1": "ok", "agy2": "logged_out", "agy8": "unknown", "claude1": "ok", "codex1": "logged_out", "grok1": "expiring", "gh1": "ok"} {
		if found[key].Status != status {
			t.Fatalf("%s: %#v", key, found[key])
		}
	}
	if _, ok := found["agy9"]; ok {
		t.Fatal("unbounded pool")
	}
	if found["agy2"].Account != "two@example.com" || found["gh1"].Account != "example-user" {
		t.Fatal(found)
	}
	facts = authHealth(context.Background(), t.TempDir(), now, func(context.Context, string) (string, error) {
		return "You are not logged into any GitHub hosts", errors.New("exit 1")
	})
	for _, h := range facts {
		if h.CLI == "gh" && h.Status != "logged_out" {
			t.Fatal(h)
		}
	}
}
func TestHealthExpiryAndUnknown(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		status model.CredStatus
		expiry time.Duration
		want   string
	}{{model.CredConfigured, time.Hour, "expiring"}, {model.CredConfigured, 48 * time.Hour, "ok"}, {model.CredExpired, -time.Hour, "logged_out"}, {model.CredUnknown, 0, "unknown"}, {model.CredFailed, 0, "unknown"}} {
		exp := now.Add(tc.expiry)
		h := healthFromCredential("codex", 1, model.Credential{Status: tc.status, ExpiresAt: &exp}, now)
		if h.Status != tc.want {
			t.Fatal(h)
		}
	}
}

func TestHealthDistinguishesObservedProviderFailure(t *testing.T) {
	h := healthFromCredential("agy", 1, model.Credential{Status: model.CredFailed, VerificationMethod: model.VerifyLiveRequest, LastError: "secret raw response"}, time.Now())
	if h.Status != "failing" || strings.Contains(h.Reason, "secret") {
		t.Fatal(h)
	}
}
