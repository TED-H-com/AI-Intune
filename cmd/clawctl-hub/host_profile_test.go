package main

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
	"time"
)

func TestCheckinDeliversLinuxHostProfileOnly(t *testing.T) {
	f := settingAPIFixture(t)
	yes := true
	if err := f.store.SaveHostProfile(model.HostProfile{LidIgnore: &yes}, store.AuditEntry{At: jobsTestNow}); err != nil {
		t.Fatal(err)
	}
	// The enrolled fixture is Linux; platform is the authenticated registry value.
	resp := settingCheckin(t, f, jobsTestNow.Add(time.Minute), "")
	if resp.HostProfile == nil || resp.HostProfile.LidIgnore == nil || !*resp.HostProfile.LidIgnore {
		t.Fatal("Linux profile missing", resp)
	}
	digest, _ := resp.HostProfile.Digest()
	if resp.HostProfileDigest != digest {
		t.Fatal("digest mismatch")
	}
	m, err := f.store.GetMachine(f.machine.id)
	if err != nil {
		t.Fatal(err)
	}
	m.OS = "darwin"
	if err = f.store.UpsertMachine(m); err != nil {
		t.Fatal(err)
	}
	resp = settingCheckin(t, f, jobsTestNow.Add(2*time.Minute), "")
	if resp.HostProfile != nil || resp.HostProfileDigest != "" {
		t.Fatal("profile delivered to non-Linux machine")
	}
}
