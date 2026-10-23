package store

import (
	"encoding/json"

	"github.com/teddashh/AI-Intune/internal/agentadapter"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// Recheck at both dispatch and claim: persisted jobs can predate an OS change.
// Windows is fail-closed; new executors must advertise Windows support in the
// shared adapter registry, or in the script catalog's allowed_os list.
func jobDispatchAllowedTx(tx dbTx, jobID, machineID string) (bool, error) {
	var osName, raw string
	err := tx.QueryRow(`SELECT COALESCE(m.os,''),d.spec FROM jobs j
 JOIN machine_registry m ON m.machine_id=j.machine_id
 JOIN desired_state d ON d.desired_id=j.desired_id
 WHERE j.job_id=? AND j.machine_id=?`, jobID, machineID).Scan(&osName, &raw)
	if err != nil {
		return false, err
	}
	if scriptcatalog.OSFamily(osName) != "windows" {
		return true, nil
	}
	return windowsJobAllowed(raw), nil
}

func windowsJobAllowed(raw string) bool {
	var spec struct {
		Kind     string `json:"kind"`
		TargetOS string `json:"target_os"`
	}
	if json.Unmarshal([]byte(raw), &spec) != nil {
		return false
	}
	switch spec.Kind {
	case "noop", model.DeviceSyncJobKind:
		return true
	case scriptcatalog.Kind:
		script, err := scriptcatalog.Decode([]byte(raw))
		if err != nil {
			return false
		}
		entry, ok := scriptcatalog.Lookup(script.ScriptID)
		return ok && entry.AllowsOS("windows")
	default:
		return spec.TargetOS == "windows" && agentadapter.ExecutorAvailableOnGOOS(spec.Kind, "windows")
	}
}
