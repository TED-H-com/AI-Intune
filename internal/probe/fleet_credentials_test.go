package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/state"
)

func TestFleetCredentialContracts(t *testing.T) {
	now := time.Now().UTC()
	token := "sk-ant-oat" + strings.Repeat("Synthetic_", 10)
	for _, tc := range []struct {
		name, provider, content string
		mode                    os.FileMode
		symlink                 bool
		want                    model.CredStatus
		finding                 bool
	}{
		{"agy refreshable", "gemini", `{"token":{"refresh_token":"synthetic-refresh","expiry":"2026-01-01T11:47:38.191882782Z"}}`, 0600, false, model.CredConfigured, false},
		{"agy offset refreshable", "gemini", `{"token":{"refresh_token":"synthetic-refresh","expiry":"2026-01-01T11:47:38.191882782-04:00"}}`, 0600, false, model.CredConfigured, false},
		{"agy no refresh", "gemini", `{"token":{"expiry":"2026-01-01T11:47:38.191882782Z"}}`, 0600, false, model.CredExpired, true},
		{"agy mode", "gemini", `{}`, 0644, false, model.CredFailed, true},
		{"agy symlink", "gemini", `{}`, 0600, true, model.CredFailed, true},
		{"agy malformed", "gemini", `{"token": "synthetic-secret"}`, 0600, false, model.CredUnknown, true},
		{"automation valid", "claude", token + "\n", 0600, false, model.CredConfigured, false},
		{"automation mode", "claude", token, 0644, false, model.CredFailed, true},
		{"automation malformed", "claude", "synthetic-secret", 0600, false, model.CredFailed, true},
		{"automation multiline", "claude", token + "\n\n", 0600, false, model.CredFailed, true},
		{"automation symlink", "claude", token, 0600, true, model.CredFailed, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".gemini", "antigravity-cli", "antigravity-oauth-token")
			if tc.provider == "claude" {
				path = filepath.Join(home, ".config", "claude-automation", "oauth-token")
				writeJSON(t, filepath.Join(home, ".claude", ".credentials.json"), map[string]any{"claudeAiOauth": map[string]any{"expiresAt": now.Add(-365 * 24 * time.Hour).UnixMilli()}})
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), tc.mode); err != nil {
				t.Fatal(err)
			}
			if tc.symlink {
				if err := os.Rename(path, path+".target"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".target", path); err != nil {
					t.Fatal(err)
				}
			}
			c := geminiCred(home, now)
			if tc.provider == "claude" {
				c = claudeCred(home, now)
			}
			if c.Status != tc.want {
				t.Fatalf("got %+v, want %s", c, tc.want)
			}
			if c.Status == model.CredConfigured && c.ExpiresAt != nil {
				t.Fatal("expiry must be omitted")
			}
			b, _ := json.Marshal(model.ObservationBatch{Credentials: []model.Credential{c}})
			for _, secret := range []string{token, "synthetic-secret", "synthetic-refresh"} {
				if strings.Contains(string(b), secret) {
					t.Fatal("secret appeared in observation")
				}
			}
			j := state.Derive(state.Facts{Now: now, EverCheckedIn: true, LastCheckinReceived: now, HasObservation: true, LastObservation: now, Credentials: []state.CredFact{{Provider: c.Provider, Source: c.Source, Status: string(c.Status), ExpiresAt: c.ExpiresAt, Note: c.Note}}, AgyPresent: true})
			found := false
			for _, f := range j.Findings {
				if f.Kind == "credential" && !f.Advisory {
					found = true
				}
			}
			if found != tc.finding {
				t.Fatalf("credential finding=%v want %v: %+v", found, tc.finding, j.Findings)
			}
		})
	}
}

func TestAutomationAbsentFallsBack(t *testing.T) {
	home := t.TempDir()
	now := time.Now()
	writeJSON(t, filepath.Join(home, ".claude", ".credentials.json"), map[string]any{"claudeAiOauth": map[string]any{"expiresAt": now.Add(time.Hour).UnixMilli()}})
	c := claudeCred(home, now)
	if c.Status != model.CredConfigured || c.ExpiresAt == nil || c.Source != "" {
		t.Fatalf("fallback: %+v", c)
	}
}

func TestLegacyGeminiNotProbed(t *testing.T) {
	home := t.TempDir()
	writeJSON(t, filepath.Join(home, ".gemini", "oauth_creds.json"), map[string]any{"expiry_date": 1})
	cs := credentials(home, time.Now())
	for _, c := range cs {
		if c.Provider == "gemini" && (c.Status != model.CredAbsent || c.ExpiresAt != nil) {
			t.Fatalf("legacy: %+v", c)
		}
	}
}

func TestFleetCredentialWrongOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("changing fixture ownership requires root")
	}
	for _, provider := range []string{"gemini", "claude"} {
		t.Run(provider, func(t *testing.T) {
			home := t.TempDir()
			path := filepath.Join(home, ".gemini", "antigravity-cli", "antigravity-oauth-token")
			if provider == "claude" {
				path = filepath.Join(home, ".config", "claude-automation", "oauth-token")
			}
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("synthetic-secret"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, 12345, -1); err != nil {
				t.Fatal(err)
			}
			c := geminiCred(home, time.Now())
			if provider == "claude" {
				c = claudeCred(home, time.Now())
			}
			if c.Status != model.CredFailed || c.Note != "credential file is not owned by current user" {
				t.Fatalf("owner: %+v", c)
			}
		})
	}
}
