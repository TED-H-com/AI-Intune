package main

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostProfileHandoff(t *testing.T) {
	dir := t.TempDir()
	yes := true
	p := model.HostProfile{LidIgnore: &yes}
	d, _ := p.Digest()
	r := model.CheckinResponse{HostProfile: &p, HostProfileDigest: d}
	if err := adoptHostProfileAt(dir, r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "host-profile.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0600 {
		t.Fatal(before.Mode())
	}
	if err = adoptHostProfileAt(dir, r); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged profile rewritten")
	}
	r.HostProfileDigest = "wrong"
	if adoptHostProfileAt(dir, r) == nil {
		t.Fatal("bad digest accepted")
	}
	if readHostApplyResult(filepath.Join(dir, "missing")) != nil {
		t.Fatal("invented result")
	}
	if err = os.WriteFile(filepath.Join(dir, "last.json"), []byte(`{"schema":"unknown"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if readHostApplyResult(filepath.Join(dir, "last.json")) != nil {
		t.Fatal("unknown schema accepted")
	}
}

func TestHostApplyResultMetadataRelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "last.json")
	for _, source := range []string{"file", "default:server", "skipped"} {
		r := model.HostApplyResult{Schema: "clawctl-fleet-apply/v1", MachineType: "server", ProfileSource: source, AppliedAt: time.Now().UTC(), Items: map[string]model.HostApplyItem{}}
		if source == "skipped" {
			r.Items["profile"] = model.HostApplyItem{Status: "skipped"}
		} else {
			r.ProfileDigest, _ = (model.HostProfile{}).Digest()
			for _, field := range []string{"lid_ignore", "disable_sleep", "power_profile", "wifi_power_save_off", "journald_max_mb", "unattended_upgrades", "scoped_sudoers", "linger", "root_disk_clean_timer"} {
				r.Items[field] = model.HostApplyItem{Status: "unmanaged"}
			}
		}
		raw, _ := json.Marshal(r)
		if err := os.WriteFile(path, raw, 0644); err != nil {
			t.Fatal(err)
		}
		got := readHostApplyResult(path)
		if got == nil || got.MachineType != "server" || got.ProfileSource != source {
			t.Fatal(got)
		}
		raw, _ = json.Marshal(model.ObservationBatch{HostProfileApply: got})
		var forwarded model.ObservationBatch
		if err := json.Unmarshal(raw, &forwarded); err != nil || forwarded.HostProfileApply.MachineType != "server" || forwarded.HostProfileApply.ProfileSource != source {
			t.Fatal(string(raw), err)
		}
	}
}
