package store

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
	"time"
)

func TestHostChecklistCompatibilityAndFreshness(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	if err := s.UpsertMachine(Machine{MachineID: "example", DisplayName: "Example", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	v, err := s.HostChecklist("example", now)
	if err != nil || v.Items[0].Status != "unknown" {
		t.Fatal(v, err)
	}
	c := model.ReadinessConfig{Path: "tailscale", SudoersPath: "/etc/sudoers.d/agent-scoped", BackupUnit: "backup.service"}
	if err = s.SaveHostReadinessConfig("example", c); err != nil {
		t.Fatal(err)
	}
	yes := true
	b := model.ObservationBatch{MeasuredAt: now, Readiness: &model.ReadinessFacts{Config: c, Tailscale: &yes, Sudoers: &yes}}
	if err = s.RecordObservation("example", b, now); err != nil {
		t.Fatal(err)
	}
	v, err = s.HostChecklist("example", now)
	if err != nil || v.Items[1].Status != "pass" || v.Items[2].Status != "pass" {
		t.Fatal(v, err)
	}
	v, _ = s.HostChecklist("example", now.Add(time.Hour))
	if v.Items[1].Status != "unknown" {
		t.Fatal("stale passed")
	}
	c.Path = "direct"
	if err = s.SaveHostReadinessConfig("example", c); err != nil {
		t.Fatal(err)
	}
	v, _ = s.HostChecklist("example", now)
	if v.Items[2].Status != "unknown" {
		t.Fatal("changed targets passed")
	}
	b.Readiness = nil
	if err = s.RecordObservation("example", b, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	v, _ = s.HostChecklist("example", now.Add(time.Second))
	if v.Items[2].Status != "unknown" {
		t.Fatal("legacy inherited facts")
	}
	for _, bad := range []model.ReadinessConfig{{Path: "other"}, {SudoersPath: "/etc/shadow"}, {BackupUnit: "--help.service"}} {
		if s.SaveHostReadinessConfig("example", bad) == nil {
			t.Fatal("accepted invalid target")
		}
	}
}
