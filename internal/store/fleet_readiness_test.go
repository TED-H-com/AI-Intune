package store

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
	"time"
)

func TestFleetReadinessAtomicDefaults(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	p, err := s.FleetReadinessProfile()
	if err != nil || p.AutoRemediateUserUnits {
		t.Fatal(p, err)
	}
	p = model.FleetReadinessProfile{Path: "tailscale", ExpectedCLIs: []string{"agy"}, ExpectedUserUnits: []string{"worker.timer"}, AutoRemediateUserUnits: true}
	if err = s.SaveFleetReadinessProfile(p, AuditEntry{At: now}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='fleet_readiness_profile' AND subject='fleet'`).Scan(&n); err != nil || n != 1 {
		t.Fatal(n, err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER reject_readiness_audit BEFORE INSERT ON audit_log WHEN NEW.action='fleet_readiness_profile' BEGIN SELECT RAISE(ABORT,'injected'); END`); err != nil {
		t.Fatal(err)
	}
	changed := p
	changed.Path = "direct"
	if s.SaveFleetReadinessProfile(changed, AuditEntry{At: now}) == nil {
		t.Fatal("audit failure committed")
	}
	saved, err := s.FleetReadinessProfile()
	if err != nil || saved.Path != "tailscale" {
		t.Fatal(saved, err)
	}
	for _, m := range []Machine{{MachineID: "a", DisplayName: "Zulu", CreatedAt: now}, {MachineID: "b", DisplayName: "Alpha", CreatedAt: now}} {
		if err = s.UpsertMachine(m); err != nil {
			t.Fatal(err)
		}
	}
	ids, err := s.ReadinessMachineIDs()
	if err != nil || len(ids) != 2 || ids[0] != "b" {
		t.Fatal(ids, err)
	}
	if err = s.SaveHostReadinessConfig("b", model.ReadinessConfig{Path: "direct"}); err != nil {
		t.Fatal(err)
	}
	c, err := s.EffectiveReadinessConfig("b")
	if err != nil || c.Path != "direct" || c.ExpectedUserUnits != "worker.timer" {
		t.Fatal(c, err)
	}
	yes := true
	facts := &model.ReadinessFacts{Config: c, Units: map[string]model.UnitFact{"worker.timer": {Loaded: &yes, Enabled: &yes, Active: &yes}}}
	if err = s.RecordObservation("b", model.ObservationBatch{MeasuredAt: now, Readiness: facts}, now); err != nil {
		t.Fatal(err)
	}
	v, err := s.HostChecklist("b", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(v.Items) != 8 || v.Config.ExpectedUserUnits != "" || v.EffectiveConfig != c || v.Items[7].Bucket != "done" || v.NeedsYou+v.Auto+v.Done != len(v.Items) {
		t.Fatal(v)
	}
	// A fleet target change must invalidate old reports.
	if _, err = s.db.Exec(`DROP TRIGGER reject_readiness_audit`); err != nil {
		t.Fatal(err)
	}
	p.ExpectedUserUnits = []string{"other.timer"}
	if err = s.SaveFleetReadinessProfile(p); err != nil {
		t.Fatal(err)
	}
	v, err = s.HostChecklist("b", now)
	if err != nil || v.Items[7].Status != "unknown" {
		t.Fatal(v, err)
	}
	if err = s.RetireMachine("a", now); err != nil {
		t.Fatal(err)
	}
	ids, err = s.ReadinessMachineIDs()
	if err != nil || len(ids) != 1 || ids[0] != "b" {
		t.Fatal(ids, err)
	}
}
