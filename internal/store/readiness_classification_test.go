package store

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"strings"
	"testing"
)

func TestReadinessClassification(t *testing.T) {
	yes, no := true, false
	off := model.UnitFact{Loaded: &yes, Enabled: &no, Active: &no, Disabled: &yes}
	idle := model.UnitFact{Loaded: &yes, Enabled: &yes, Active: &no, Oneshot: &yes, Failed: &no}
	lastFailed := idle
	lastFailed.Failed = &yes
	missing := model.UnitFact{Loaded: &no}
	failed := off
	failed.Remediation = &model.Remediation{Reason: "denied\n" + strings.Repeat("x", 300)}
	for _, tc := range []struct {
		name, key, status, path, sudo string
		auto                          bool
		unit                          model.UnitFact
		want                          string
		action                        string
	}{
		{name: "oneshot idle", key: "unit:backup.service", status: "pass", auto: true, unit: idle, want: "done"},
		{name: "oneshot failed", key: "unit:backup.service", status: "fail", auto: true, unit: lastFailed, want: "needs_you", action: "Last run failed; check the unit on the machine"},
		{name: "pass", key: "checkin", status: "pass", want: "done"},
		{name: "first checkin", key: "checkin", status: "unknown", want: "auto", action: "Waiting for the first report"},
		{name: "offline", key: "checkin", status: "fail", want: "needs_you", action: "off or unreachable"},
		{name: "no path", key: "reachability", status: "unknown", want: "needs_you", action: "Choose an access path"},
		{name: "tailscale waiting", key: "reachability", status: "unknown", path: "tailscale", want: "auto"},
		{name: "tailscale approval", key: "reachability", status: "fail", path: "tailscale", want: "needs_you", action: "admin console"},
		{name: "manual ssh", key: "reachability", status: "unknown", path: "direct", want: "needs_you", action: "Verify SSH"},
		{name: "sudo target missing", key: "sudoers", status: "unknown", want: "needs_you"},
		{name: "sudo waiting", key: "sudoers", status: "unknown", sudo: "/etc/sudoers.d/scoped", want: "auto"},
		{name: "sudo missing", key: "sudoers", status: "fail", sudo: "/etc/sudoers.d/scoped", want: "needs_you"},
		{name: "oauth", key: "signin:agy", status: "fail", want: "needs_you", action: "OAuth consent"},
		{name: "cli waiting", key: "signin:agy", status: "unknown", want: "auto"},
		{name: "notifications", key: "notifications", status: "fail", want: "needs_you"},
		{name: "backup waiting", key: "backup_unit", status: "unknown", want: "auto"},
		{name: "backup missing", key: "backup_unit", status: "fail", want: "needs_you"},
		{name: "backup old", key: "backup_recent", status: "fail", want: "needs_you"},
		{name: "backup job off repair", key: "backup_unit", status: "fail", auto: true, unit: off, want: "auto"},
		{name: "backup off repair", key: "backup_recent", status: "fail", auto: true, unit: off, want: "auto"},
		{name: "unit waiting", key: "unit:backup.service", status: "unknown", want: "auto"},
		{name: "unit absent", key: "unit:backup.service", status: "fail", auto: true, unit: missing, want: "needs_you", action: "host bootstrap"},
		{name: "unit off", key: "unit:backup.service", status: "fail", unit: off, want: "needs_you"},
		{name: "unit repair", key: "unit:backup.service", status: "fail", auto: true, unit: off, want: "auto"},
		{name: "repair failed", key: "unit:backup.service", status: "fail", auto: true, unit: failed, want: "needs_you", action: "denied "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			item := ReadinessItem{Key: tc.key, Status: tc.status, Name: "Example", Doc: "doc"}
			got := classifyReadiness(item, model.ReadinessConfig{Path: tc.path, SudoersPath: tc.sudo, BackupUnit: "backup.service", AutoRemediate: tc.auto}, map[string]model.UnitFact{"backup.service": tc.unit})
			if got.Bucket != tc.want || (got.Owner == "you") != (tc.want == "needs_you") || got.Status != item.Status || got.Name != item.Name || got.Doc != item.Doc || !strings.Contains(got.NextAction, tc.action) {
				t.Fatalf("%+v", got)
			}
			if strings.ContainsAny(got.NextAction, "\n\x1b") || len(got.NextAction) > 250 {
				t.Fatal("unbounded or unsafe reason")
			}
		})
	}
}
