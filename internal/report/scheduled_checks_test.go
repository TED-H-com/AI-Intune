package report

import (
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/scheduledcheck"
)

func TestScheduledChecksSection(t *testing.T) {
	for _, tc := range []struct {
		name, status, want string
		streak             int
	}{
		{"failure", "failed", "failed (2026-09-03 08:00 UTC)", 5},
		{"never ran", "not_run", "not run (2026-09-03 08:00 UTC)", 0},
		{"pending", "pending", "awaiting result", 0},
		{"all pass", "passed", "all 1 targets passed", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := base()
			in.ScheduledChecks = []scheduledcheck.Schedule{{Name: "fleet-daily-health", Targets: []scheduledcheck.Result{{DisplayName: "Sample worker", Status: tc.status, At: now, InWindow: true, ConsecutiveFailures: tc.streak, Reason: "create private script directory\nignored line"}}}}
			got := Render(in)
			for _, want := range []string{"Scheduled checks", "fleet-daily-health", tc.want} {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %q: %s", want, got)
				}
			}
			if tc.status != "passed" && !strings.Contains(got, "Sample worker") {
				t.Fatal(got)
			}
			if tc.streak > 1 && !strings.Contains(got, "failed 5 runs in a row") {
				t.Fatal(got)
			}
			if strings.Contains(got, "ignored line") || strings.Contains(got, "alive; 0 changes") {
				t.Fatal(got)
			}
		})
	}
}

func TestScheduledChecksOutsideWindowAndUntargeted(t *testing.T) {
	in := base()
	in.ScheduledChecks = []scheduledcheck.Schedule{{Name: "weekly-check", Targets: []scheduledcheck.Result{{Status: "failed", Reason: "old failure", At: now}}}}
	in.UntargetedMachines = []string{"New worker"}
	got := Render(in)
	if !strings.Contains(got, "weekly-check: no runs due in this report window") || !strings.Contains(got, "New worker: not targeted by any enabled schedule") || strings.Contains(got, "old failure") {
		t.Fatal(got)
	}
}

func TestScheduledChecksAreNotHiddenByMachineStateLimit(t *testing.T) {
	in := base()
	for i := 0; i < MaxLines+1; i++ {
		in.Machines = append(in.Machines, Machine{ID: string(rune('a' + i)), DisplayName: "Offline worker", State: "Unreachable"})
	}
	in.ScheduledChecks = []scheduledcheck.Schedule{{Name: "daily", Targets: []scheduledcheck.Result{{DisplayName: "Failing worker", Status: "failed", At: now, InWindow: true, Reason: "check failed"}}}}
	if got := Render(in); !strings.Contains(got, "Failing worker — daily: failed") {
		t.Fatal(got)
	}
}

func TestScheduledChecksPartialSuccess(t *testing.T) {
	in := base()
	in.ScheduledChecks = []scheduledcheck.Schedule{{Name: "daily", Targets: []scheduledcheck.Result{
		{DisplayName: "Passing worker", Status: "passed", At: now, InWindow: true},
		{DisplayName: "Failing worker", Status: "failed", At: now, InWindow: true, Reason: "check failed"},
	}}}
	got := Render(in)
	if strings.Contains(got, "all 2 targets passed") || strings.Contains(got, "Passing worker") || !strings.Contains(got, "Failing worker") {
		t.Fatal(got)
	}
	in.ScheduledChecks[0].Targets[1].Status = "passed"
	got = Render(in)
	if !strings.Contains(got, "daily: all 2 targets passed") {
		t.Fatal(got)
	}
}
