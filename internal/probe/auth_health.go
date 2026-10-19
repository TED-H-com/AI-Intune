package probe

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

// AuthHealth reuses credential parsing; no token values are added to observations.
func AuthHealth(ctx context.Context, home string, now time.Time) []model.AuthHealth {
	return authHealth(ctx, home, now, ghAuthStatus)
}

func authHealth(ctx context.Context, home string, now time.Time, gh func(context.Context, string) (string, error)) []model.AuthHealth {
	out := []model.AuthHealth{}
	for _, p := range []struct {
		name string
		cred func(string, time.Time) model.Credential
	}{{"codex", codexCred}, {"claude", claudeCred}, {"grok", grokCred}, {"agy", geminiCred}} {
		h := healthFromCredential(p.name, 1, p.cred(home, now), now)
		h.Account = authAccount(home, p.name)
		out = append(out, h)
	}
	for slot := 2; slot <= 8; slot++ {
		h := filepath.Join(home, ".gemini", "antigravity-accounts", "acct"+string(rune('0'+slot))+"-home")
		// Never follow an account-home symlink outside the supported pool.
		if st, e := os.Lstat(h); e == nil && st.IsDir() && st.Mode()&os.ModeSymlink == 0 {
			health := healthFromCredential("agy", slot, geminiCred(h, now), now)
			health.Account = authAccount(h, "agy")
			out = append(out, health)
		}
	}
	status := model.AuthHealth{CLI: "gh", Slot: 1, Status: "unknown", Reason: "GitHub sign-in could not be checked"}
	text, err := gh(ctx, home)
	if m := ghLogin.FindStringSubmatch(text); len(m) > 1 {
		status.Account = m[1]
	}
	if err == nil && status.Account != "" {
		status.Status = "ok"
		status.Reason = "GitHub reports signed in"
	} else if strings.Contains(text, "not logged") || strings.Contains(text, "token") && strings.Contains(text, "invalid") {
		status.Status = "logged_out"
		status.Reason = "GitHub reports signed out"
	}
	out = append(out, status)
	// No documented, stable Hermes auth-store schema is present in this tree.
	out = append(out, model.AuthHealth{CLI: "hermes-openai-codex", Slot: 1, Status: "unknown", Reason: "Hermes provider status is unavailable; sign-in is not supported from the Hub"})
	return out
}

var ghLogin = regexp.MustCompile(`Logged in to github\.com account ([A-Za-z0-9-]{1,39})`)

func ghAuthStatus(ctx context.Context, home string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	dirs := append([]string{filepath.Join(home, ".local", "bin"), filepath.Join(home, ".grok", "bin")}, filepath.SplitList(os.Getenv("PATH"))...)
	binary, ok := lookPathIn(dirs, "gh")
	if !ok {
		return "", exec.ErrNotFound
	}
	cmd := exec.CommandContext(ctx, binary, "auth", "status", "--hostname", "github.com")
	cmd.Env = append(os.Environ(), "HOME="+home, "GH_PROMPT_DISABLED=1")
	// status never requests --show-token; cap even a broken CLI's output.
	b := &authStatusBuffer{}
	cmd.Stdout = b
	cmd.Stderr = b
	err := cmd.Run()
	return b.text, err
}

type authStatusBuffer struct{ text string }

func (b *authStatusBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if len(b.text) < 8192 {
		left := 8192 - len(b.text)
		if len(p) > left {
			p = p[:left]
		}
		b.text += string(p)
	}
	return n, nil
}
func healthFromCredential(cli string, slot int, c model.Credential, now time.Time) model.AuthHealth {
	h := model.AuthHealth{CLI: cli, Slot: slot, Status: "unknown", Reason: "Local sign-in status is unknown", ExpiresAt: c.ExpiresAt, LastSuccessAt: c.VerifiedAt}
	switch c.Status {
	case model.CredConfigured:
		h.Status = "ok"
		h.Reason = "Local sign-in file is configured; provider access has not been tested"
	case model.CredAbsent, model.CredExpired:
		h.Status = "logged_out"
		h.Reason = "Sign-in is missing or expired"
	case model.CredFailed:
		h.Status = "unknown"
		h.Reason = "Sign-in file could not be safely read"
		if c.VerificationMethod == model.VerifyLiveRequest {
			h.Status, h.Reason = "failing", "Recent provider request failed"
		}
	}
	if h.Status == "ok" && c.ExpiresAt != nil && c.ExpiresAt.Before(now.Add(24*time.Hour)) {
		h.Status = "expiring"
		h.Reason = "Local sign-in expires within 24 hours"
	}
	return h
}

// Only explicitly named plain metadata fields are inspected. JWTs are never
// decoded for identity; the existing Codex expiry parser remains unchanged.
func authAccount(home, cli string) string {
	paths := map[string]string{"agy": filepath.Join(home, ".gemini", "antigravity-cli", "antigravity-oauth-token"), "codex": filepath.Join(home, ".codex", "codex-accounts.json"), "claude": filepath.Join(home, ".claude.json"), "grok": filepath.Join(home, ".grok", "auth.json")}
	b, _, _ := privateCredential(cli, "metadata", paths[cli], false)
	if b == nil {
		return ""
	}
	var doc struct {
		Email           string `json:"email"`
		Login           string `json:"login"`
		ActiveAccountID string `json:"activeAccountId"`
		User            struct {
			Email string `json:"email"`
		} `json:"user"`
		OAuth struct {
			Email string `json:"emailAddress"`
		} `json:"oauthAccount"`
	}
	if json.Unmarshal(b, &doc) != nil {
		return ""
	}
	for _, v := range []string{doc.Email, doc.User.Email, doc.OAuth.Email, doc.ActiveAccountID} {
		if plainEmail.MatchString(v) {
			return v
		}
	}
	return ""
}

var plainEmail = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]{1,64}@[A-Za-z0-9.-]{1,189}$`)
