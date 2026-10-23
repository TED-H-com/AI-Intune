package store

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
	"time"
)

func TestHostProfilePersistenceAndStatus(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	v, err := s.FleetHostProfile(now)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := v.Profile.Canonical()
	if string(b) != "{}" {
		t.Fatal(string(b))
	}
	yes := true
	p := model.HostProfile{LidIgnore: &yes}
	if err = s.SaveHostProfile(p, AuditEntry{At: now}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='fleet_host_profile'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal(n)
	}
	for _, m := range []Machine{{MachineID: "linux", DisplayName: "Laptop", OS: "linux", CreatedAt: now}, {MachineID: "mac", DisplayName: "Mac", OS: "darwin", CreatedAt: now}} {
		if err = s.UpsertMachine(m); err != nil {
			t.Fatal(err)
		}
	}
	v, err = s.FleetHostProfile(now)
	if err != nil || len(v.Hosts) != 1 || v.Hosts[0].Status != "Waiting" {
		t.Fatal(v, err)
	}
	d, _ := p.Digest()
	result := &model.HostApplyResult{Schema: "clawctl-fleet-apply/v1", ProfileDigest: d, AppliedAt: now, Items: map[string]model.HostApplyItem{"lid_ignore": {Status: "ok"}}}
	for _, name := range []string{"disable_sleep", "power_profile", "wifi_power_save_off", "journald_max_mb", "unattended_upgrades", "scoped_sudoers", "linger", "root_disk_clean_timer"} {
		result.Items[name] = model.HostApplyItem{Status: "unmanaged"}
	}
	if err = s.RecordObservation("linux", model.ObservationBatch{MeasuredAt: now, HostProfileApply: result}, now); err != nil {
		t.Fatal(err)
	}
	v, err = s.FleetHostProfile(now)
	if err != nil || v.Hosts[0].Status != "Up to date" || v.Hosts[0].DisplayName != "Laptop" {
		t.Fatal(v, err)
	}
	v, _ = s.FleetHostProfile(now.Add(time.Hour))
	if v.Hosts[0].Status != "Waiting" {
		t.Fatal(v)
	}
	result.Items["lid_ignore"] = model.HostApplyItem{Status: "failed"}
	if err = s.RecordObservation("linux", model.ObservationBatch{MeasuredAt: now, HostProfileApply: result}, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	v, _ = s.FleetHostProfile(now.Add(time.Second))
	if v.Hosts[0].Status != "Failed" {
		t.Fatal(v)
	}
}

func TestHostProfileSharedDisclosureCountsLinuxOnly(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	for _, m := range []Machine{{MachineID: "linux", DisplayName: "Laptop", OS: "linux", CreatedAt: now}, {MachineID: "mac", DisplayName: "Mac", OS: "darwin", CreatedAt: now}} {
		if err := s.UpsertMachine(m); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.SaveHostProfile(model.HostProfile{}, AuditEntry{At: now}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]int64{"linux": 1, "mac": 0} {
		rows, err := s.MachineDataHoldings(id)
		if err != nil {
			t.Fatal(err)
		}
		h := holdingFor(t, rows, "fleet_host_profile")
		if h.Rows != want || h.Dated != 0 {
			t.Fatal(id, h)
		}
	}
}
