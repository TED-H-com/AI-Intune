package store

import (
	"fmt"
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
	result := &model.HostApplyResult{Schema: "clawctl-fleet-apply/v1", MachineType: "laptop", ProfileSource: "file", ProfileDigest: d, AppliedAt: now, Items: map[string]model.HostApplyItem{"lid_ignore": {Status: "ok"}}}
	for _, name := range []string{"disable_sleep", "power_profile", "wifi_power_save_off", "journald_max_mb", "unattended_upgrades", "scoped_sudoers", "linger", "root_disk_clean_timer"} {
		result.Items[name] = model.HostApplyItem{Status: "unmanaged"}
	}
	if err = s.RecordObservation("linux", model.ObservationBatch{MeasuredAt: now, HostProfileApply: result}, now); err != nil {
		t.Fatal(err)
	}
	v, err = s.FleetHostProfile(now)
	if err != nil || v.Hosts[0].Status != "Up to date" || v.Hosts[0].DisplayName != "Laptop" || v.Hosts[0].Result.MachineType != "laptop" || v.Hosts[0].Result.ProfileSource != "file" {
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

func TestHostProfileProjectionColumnMigration(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	if err := s.UpsertMachine(Machine{MachineID: "linux", OS: "linux", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	// Old reports omit metadata. Removing the projection columns recreates the
	// pre-upgrade shape without changing the immutable observation ledger.
	for _, col := range []string{"machine_type", "profile_source"} {
		if _, err := s.db.Exec("ALTER TABLE observed_latest DROP COLUMN " + col); err != nil {
			t.Fatal(err)
		}
	}
	for i, payload := range []string{
		`{"schema":"clawctl-fleet-apply/v1","items":{"profile":{"status":"failed"}}}`,
		`{"schema":"clawctl-fleet-apply/v1","machine_type":"server","profile_source":"default:server"}`,
	} {
		if _, err := s.db.Exec(`INSERT INTO observed_latest(machine_id,kind,subject,observation_id,measured_at,received_at,payload,source,observation_sequence) VALUES('linux','host_profile_apply',?,?,'','',?,'agent',1)`, fmt.Sprint(i), fmt.Sprint(i), payload); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err := addMissingColumns(s.db); err != nil {
			t.Fatal(err)
		}
	}
	for i, want := range [][2]string{{"", ""}, {"server", "default:server"}} {
		var machine, source string
		if err := s.rdb.QueryRow(`SELECT machine_type,profile_source FROM observed_latest WHERE subject=?`, fmt.Sprint(i)).Scan(&machine, &source); err != nil {
			t.Fatal(err)
		}
		if machine != want[0] || source != want[1] {
			t.Fatal(machine, source)
		}
	}
}
