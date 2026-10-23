package store

import (
	"errors"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/agentadapter"
	"github.com/teddashh/AI-Intune/internal/model"
)

func TestWindowsJobTypeGate(t *testing.T) {
	for _, kind := range []string{"systemd", "apt", "disk-cleanup", "maintenance", "maintenance-disk-clean", "bat-server", "hermes-agent", "openclaw", "tailscale", "future-unknown-job"} {
		if windowsJobAllowed(`{"kind":"` + kind + `","target_os":"windows"}`) {
			t.Errorf("Linux/unknown job accepted: %s", kind)
		}
	}
	for _, contract := range agentadapter.Contracts() {
		for _, osName := range []string{"windows", "linux", "darwin", ""} {
			raw := `{"kind":"` + contract.ExecutorKind + `","target_os":"` + osName + `"}`
			want := osName == "windows" && agentadapter.ExecutorAvailableOnGOOS(contract.ExecutorKind, "windows")
			if got := windowsJobAllowed(raw); got != want {
				t.Errorf("%s on %s: %t want %t", contract.ExecutorKind, osName, got, want)
			}
		}
	}
	for _, raw := range []string{`{"kind":"noop"}`, model.DeviceSyncSpecJSON} {
		if !windowsJobAllowed(raw) {
			t.Errorf("portable job rejected: %s", raw)
		}
	}
	for _, raw := range []string{`{`, `{}`, `{"kind":"script_v1","script_id":"fleet-probe-v1"}`} {
		if windowsJobAllowed(raw) {
			t.Errorf("invalid/Linux script accepted: %s", raw)
		}
	}
}

func TestWindowsDispatchAndClaimRecheckMachineOS(t *testing.T) {
	s := newDeployTestStore(t)
	registerDeployMachine(t, s, "machine-a")
	makeJob := func(resource, spec string) string {
		t.Helper()
		desired, rev, err := s.CreateDesiredState("machine", "machine-a", "app", resource, `{}`, "test")
		if err != nil {
			t.Fatal(err)
		}
		id, err := s.CreateJob("machine-a", desired, rev, NewJob{})
		if err != nil {
			t.Fatal(err)
		}
		// Model an existing queued job, including legacy jobs predating OS gating.
		if _, err := s.DB().Exec(`UPDATE desired_state SET spec=? WHERE desired_id=?`, spec, desired); err != nil {
			t.Fatal(err)
		}
		return id
	}
	linuxJob := makeJob("linux-only", `{"kind":"openclaw"}`)
	portableJob := makeJob("portable", `{"kind":"noop"}`)
	if _, err := s.DB().Exec(`UPDATE machine_registry SET os='linux' WHERE machine_id='machine-a'`); err != nil {
		t.Fatal(err)
	}
	if job, ok, err := s.NextJobForMachine("machine-a"); err != nil || !ok || job.JobID != linuxJob {
		t.Fatal("Linux job unavailable", err)
	}
	// A queued job can outlive platform identity updates. Claim must recheck.
	if _, err := s.DB().Exec(`UPDATE machine_registry SET os='Windows 11 Pro' WHERE machine_id='machine-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ClaimJob(linuxJob, "machine-a", deployTestNow, time.Minute); !errors.Is(err, ErrJobNotFound) {
		t.Fatalf("Windows claimed Linux job: %v", err)
	}
	if job, ok, err := s.NextJobForMachine("machine-a"); err != nil || !ok || job.JobID != portableJob {
		t.Fatal("blocked job starved portable job", err)
	}
	if _, err := s.ClaimJob(portableJob, "machine-a", deployTestNow, time.Minute); err != nil {
		t.Fatal("portable job claim failed", err)
	}
	if _, ok, err := s.NextJobForMachine("machine-a"); err != nil || ok {
		t.Fatal("Linux job dispatched to Windows", err)
	}
}
