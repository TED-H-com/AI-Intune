package operator

import (
	"fmt"
	"time"

	"github.com/teddashh/AI-Intune/internal/scheduledcheck"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// ScheduledCheckReports reuses the read-report presentation without exposing
// raw script output. Missing recent slots supersede older successful jobs.
func (s *Service) ScheduledCheckReports(now time.Time) (map[string][]ReadReport, error) {
	schedules, err := s.store.ScheduledChecks(now.Add(-30*24*time.Hour), now, false)
	if err != nil {
		return nil, err
	}
	out := map[string][]ReadReport{}
	for _, schedule := range schedules {
		if scriptcatalog.IsReadReport(schedule.ScriptID) {
			continue
		}
		for _, target := range schedule.Targets {
			out[target.MachineID] = append(out[target.MachineID], projectScheduledCheck(schedule, target))
		}
	}
	return out, nil
}

func projectScheduledCheck(schedule scheduledcheck.Schedule, target scheduledcheck.Result) ReadReport {
	name := map[string]string{
		"fleet-probe-v1": "Fleet health", "bat-sweep-report-v1": "BAT health",
		"disk-deep-report-v1": "Disk usage", "disk-safe-preview-v2": "Disk cleanup preview",
		"disk-safe-clean-v2": "Disk cleanup", "disk-quarantine-expire-v1": "Disk quarantine cleanup",
	}[schedule.ScriptID]
	if name == "" {
		name = "Scheduled check"
	}
	out := ReadReport{ScriptID: schedule.ScriptID, Name: name + " — " + scheduledcheck.Text(schedule.Name, 100), Status: target.Status, Badge: "Not run", Class: "st dim", Summary: scheduledcheck.Reason(target.Reason)}
	if !target.At.IsZero() {
		out.RanAt = target.At.UTC().Format(time.RFC3339)
	}
	switch target.Status {
	case "passed":
		out.Badge, out.Class, out.Summary = "Passed", "st green", "The scheduled check passed."
	case "failed":
		out.Badge, out.Class = "Failed", "st red"
	}
	if target.ConsecutiveFailures >= scheduledcheck.HistoryLimit {
		out.Findings = append(out.Findings, fmt.Sprintf("Failed at least %d runs in a row.", target.ConsecutiveFailures))
	} else if target.ConsecutiveFailures > 1 {
		out.Findings = append(out.Findings, fmt.Sprintf("Failed %d runs in a row.", target.ConsecutiveFailures))
	}
	return out
}
