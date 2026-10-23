package probe

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestReadinessFixtures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux collector")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	for name, body := range map[string]string{"tailscale": "echo '{\"BackendState\":\"Running\"}'", "systemctl": "printf 'LoadState=loaded\\nResult=success\\nExecMainStatus=0\\nExecMainExitTimestamp=@1700000000\\n'"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
	}
	c := model.ReadinessConfig{BackupUnit: "backup.service", SudoersPath: "/etc/sudoers.d/nonexistent-readiness-fixture"}
	f := CollectReadiness(context.Background(), c, []model.Credential{{Provider: "codex", Status: model.CredConfigured}, {Provider: "claude", Status: model.CredUnknown}, {Provider: "grok", Status: model.CredAbsent}})
	if f.Tailscale == nil || !*f.Tailscale || f.BackupPresent == nil || !*f.BackupPresent || f.BackupLastSuccess == nil || f.SignedIn["codex"] == nil || !*f.SignedIn["codex"] || f.SignedIn["claude"] != nil || *f.SignedIn["grok"] {
		t.Fatalf("unexpected typed facts: %+v", f)
	}
	t.Setenv("PATH", t.TempDir())
	f = CollectReadiness(context.Background(), c, nil)
	if f.Tailscale != nil || f.BackupPresent != nil {
		t.Fatal("command failure became failure evidence")
	}
}
