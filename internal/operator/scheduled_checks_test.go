package operator

import (
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/scheduledcheck"
)

func TestScheduledCheckBadges(t *testing.T) {
	for _, tc := range []struct{ status, badge, class string }{
		{"passed", "Passed", "st green"}, {"failed", "Failed", "st red"}, {"not_run", "Not run", "st dim"}, {"pending", "Not run", "st dim"},
	} {
		t.Run(tc.status, func(t *testing.T) {
			r := scheduledcheck.Result{Status: tc.status, At: time.Date(2026, 10, 19, 16, 0, 0, 0, time.UTC), Reason: "create private script directory\nignored", ConsecutiveFailures: 5}
			got := projectScheduledCheck(scheduledcheck.Schedule{ScriptID: "fleet-probe-v1", Name: "fleet-daily-health"}, r)
			if got.Badge != tc.badge || got.Class != tc.class || got.RanAt != "2026-10-19T16:00:00Z" || got.Name != "Fleet health — fleet-daily-health" {
				t.Fatalf("projection: %+v", got)
			}
			if strings.Contains(got.Summary, "ignored") || strings.Contains(got.Summary, "script_v1") {
				t.Fatal("unexpected summary")
			}
		})
	}
}

func TestFleetProbeV2CheckLabel(t *testing.T) {
	got := projectScheduledCheck(scheduledcheck.Schedule{ScriptID: "fleet-probe-v2", Name: "fleet-daily-health"}, scheduledcheck.Result{Status: "not_run"})
	if got.Name != "Fleet health — fleet-daily-health" {
		t.Fatalf("label: %s", got.Name)
	}
}
