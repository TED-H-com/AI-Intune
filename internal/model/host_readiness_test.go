package model

import (
	"strings"
	"testing"
)

func TestFleetReadinessValidation(t *testing.T) {
	for _, p := range []FleetReadinessProfile{
		{}, {Path: "tailscale", SudoersPath: "/etc/sudoers.d/agent-scoped", BackupUnit: "backup.service", ExpectedCLIs: []string{"agy", "codex"}, ExpectedUserUnits: []string{"backup.timer", "worker@sample.service"}},
	} {
		if err := p.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []FleetReadinessProfile{
		{Path: "ssh"}, {SudoersPath: "/etc/shadow"}, {BackupUnit: "backup.timer"}, {ExpectedCLIs: []string{"other"}}, {ExpectedCLIs: []string{"agy", "agy"}},
		{ExpectedUserUnits: []string{"--bad.service"}}, {ExpectedUserUnits: []string{"../bad.service"}}, {ExpectedUserUnits: []string{"bad.service\n"}}, {ExpectedUserUnits: []string{strings.Repeat("a", 129) + ".service"}}, {ExpectedUserUnits: make([]string, 17)},
		{ExpectedUserUnits: []string{"a.service", "a.service"}},
	} {
		if p.Validate() == nil {
			t.Fatalf("accepted %+v", p)
		}
	}
}
func TestFleetReadinessEffective(t *testing.T) {
	p := FleetReadinessProfile{Path: "tailscale", SudoersPath: "/etc/sudoers.d/scoped", BackupUnit: "backup.service", ExpectedUserUnits: []string{"z.timer", "a.service"}, AutoRemediateUserUnits: true}
	c := p.Effective(ReadinessConfig{Path: "direct"})
	if c.Path != "direct" || c.SudoersPath != p.SudoersPath || c.BackupUnit != p.BackupUnit || c.ExpectedUserUnits != "a.service,z.timer" || !c.AutoRemediate {
		t.Fatal(c)
	}
	if p.ExpectedUserUnits[0] != "z.timer" {
		t.Fatal("effective config mutated profile")
	}
	if p.Effective(ReadinessConfig{}) != p.Effective(ReadinessConfig{}) {
		t.Fatal("non-comparable config")
	}
	if (FleetReadinessProfile{}).Effective(ReadinessConfig{}).AutoRemediate {
		t.Fatal("repair enabled by default")
	}
}
