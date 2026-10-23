package operator

import (
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/store"
	"reflect"
)

type DiskPolicyChange struct{ Field, Before, After string }

// DiskPolicyChanges compares canonical typed policy fields for human review.
func DiskPolicyChanges(before, after json.RawMessage) []DiskPolicyChange {
	old := store.DefaultDiskPolicy()
	next := old
	json.Unmarshal(before, &old)
	json.Unmarshal(after, &next)
	labels := []string{"Observed data mounts", "Canary days", "Growth policy (GB/hour, window minutes)", "Schema version", "User temporary files: minimum days", "System temporary files: minimum days", "Docker: minimum hours", "Docker cleanup mode", "Journal size cap (MiB)", "Cargo: minimum days", "uv mode", "npm mode", "Tool cache mode", "Additional protected paths", "Warning usage (%)", "Critical usage (%)", "Deep report above (%)", "Quarantine retention (days)", "Scan item limit", "Scan entry limit", "Scan time limit (seconds)"}
	fields := func(p store.DiskPolicy) []any {
		return []any{p.DataMounts, p.CanaryDays, p.Growth, p.SchemaVersion, p.SafeTier.UserTmpMinDays, p.SafeTier.VarTmpMinDays, p.SafeTier.DockerMinHours, p.SafeTier.DockerMode, p.SafeTier.JournaldMaxMiB, p.SafeTier.CargoMinDays, p.SafeTier.UVMode, p.SafeTier.NPMMode, p.SafeTier.ToolCacheMode, p.ProtectPaths, p.Thresholds.WarnPercent, p.Thresholds.CriticalPercent, p.Thresholds.DeepReportAbovePercent, p.QuarantineTTLDays, p.ScanBudgets.MaxItems, p.ScanBudgets.MaxEntries, p.ScanBudgets.MaxSeconds}
	}
	a, b := fields(old), fields(next)
	out := []DiskPolicyChange{}
	for i := range a {
		if len(before) == 0 || !reflect.DeepEqual(a[i], b[i]) {
			previous := fmt.Sprint(a[i])
			if len(before) == 0 {
				previous = "Not configured"
			}
			out = append(out, DiskPolicyChange{labels[i], previous, fmt.Sprint(b[i])})
		}
	}
	return out
}
