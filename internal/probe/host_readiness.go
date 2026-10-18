package probe

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"runtime"
	"strings"
)

// CollectReadiness measures as the agent service user. It never invokes sudo or login.
func CollectReadiness(ctx context.Context, c model.ReadinessConfig, creds []model.Credential) *model.ReadinessFacts {
	f := &model.ReadinessFacts{Config: c, SignedIn: map[string]*bool{}}
	if runtime.GOOS != "linux" {
		return f
	}
	f.ServiceUser = unixUser()
	if strings.HasPrefix(c.SudoersPath, "/etc/sudoers.d/") && !strings.Contains(c.SudoersPath, "..") {
		st, err := os.Lstat(c.SudoersPath)
		if err == nil {
			v := st.Mode().IsRegular()
			f.Sudoers = &v
		} else if os.IsNotExist(err) {
			v := false
			f.Sudoers = &v
		}
	}
	out, _, err := run(ctx, cmdTimeout, "tailscale", "status", "--json")
	if err == nil {
		var v struct{ BackendState string }
		if json.Unmarshal([]byte(out), &v) == nil && v.BackendState != "" {
			b := v.BackendState == "Running"
			f.Tailscale = &b
		}
	}
	for _, cred := range creds {
		name := cred.Provider
		if name == "gemini" {
			name = "agy"
		}
		if name != "claude" && name != "codex" && name != "grok" && name != "agy" {
			continue
		}
		switch cred.Status {
		case model.CredConfigured:
			v := true
			f.SignedIn[name] = &v
		case model.CredAbsent, model.CredExpired, model.CredFailed:
			v := false
			f.SignedIn[name] = &v
		}
	}
	if c.BackupUnit != "" && !strings.HasPrefix(c.BackupUnit, "-") && !strings.ContainsAny(c.BackupUnit, " /\\\n") {
		out, _, err = run(ctx, cmdTimeout, "systemctl", "--user", "show", c.BackupUnit, "--timestamp=unix", "-p", "LoadState", "-p", "Result", "-p", "ExecMainStatus", "-p", "ExecMainExitTimestamp")
		if err == nil {
			p := parseProps(out)
			if p["LoadState"] != "" {
				b := p["LoadState"] != "not-found"
				f.BackupPresent = &b
			}
			if p["Result"] == "success" && p["ExecMainStatus"] == "0" {
				f.BackupLastSuccess = parseSystemdTime(p["ExecMainExitTimestamp"])
			}
		}
	}
	return f
}
