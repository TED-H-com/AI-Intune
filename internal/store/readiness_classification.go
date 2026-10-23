package store

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"strings"
)

// classifyReadiness assigns responsibility without changing measurement status.
func classifyReadiness(i ReadinessItem, c model.ReadinessConfig, units map[string]model.UnitFact) ReadinessItem {
	if strings.HasPrefix(i.Key, "unit:") {
		u := units[strings.TrimPrefix(i.Key, "unit:")]
		if u.Loaded != nil {
			i.Status = "fail"
			if model.UnitOK(u) {
				i.Status = "pass"
			}
		}
	}
	i.Owner = "hub"
	i.Bucket = "done"
	if i.Status == "pass" {
		return i
	}
	i.Owner = "you"
	i.Bucket = "needs_you"
	auto := func(action string) { i.Owner = "hub"; i.Bucket = "auto"; i.NextAction = action }
	switch {
	case i.Key == "checkin":
		if i.Status == "unknown" {
			auto("Waiting for the first report")
		} else {
			i.NextAction = "The machine is off or unreachable. Turn it on and check its connection."
		}
	case i.Key == "reachability":
		switch c.Path {
		case "":
			i.NextAction = "Choose an access path."
		case "tailscale":
			if i.Status == "unknown" {
				auto("Waiting for the first report")
			} else {
				i.NextAction = "Approve the machine in the Tailscale admin console."
			}
		default:
			i.NextAction = "Verify SSH access from your operator computer."
		}
	case i.Key == "sudoers":
		if i.Status == "unknown" && c.SudoersPath != "" {
			auto("Waiting for the first report")
		} else if c.SudoersPath == "" {
			i.NextAction = "Choose the scoped sudoers drop-in."
		}
	case strings.HasPrefix(i.Key, "signin:"):
		if i.Status == "unknown" {
			auto("Waiting for the first report")
		} else {
			i.NextAction = "Sign in interactively as the agent service user and approve OAuth consent."
		}
	case strings.HasPrefix(i.Key, "unit:"), i.Key == "backup_unit", i.Key == "backup_recent":
		unit := strings.TrimPrefix(i.Key, "unit:")
		if !strings.HasPrefix(i.Key, "unit:") {
			unit = c.BackupUnit
		}
		u := units[unit]
		switch {
		case u.Oneshot != nil && *u.Oneshot && u.Failed != nil && *u.Failed:
			i.NextAction = "Last run failed; check the unit on the machine"
		case u.Remediation != nil && !u.Remediation.OK:
			i.NextAction = "Could not turn on the unit: " + model.SafeReadinessReason(u.Remediation.Reason)
		case u.Loaded != nil && !*u.Loaded:
			i.NextAction = "Install this unit with the host bootstrap, then wait for the next report."
		case i.Key == "backup_unit" && i.Status == "fail" && u.Loaded == nil:
			i.NextAction = "Install this unit with the host bootstrap, then wait for the next report."
		case i.Status == "unknown":
			auto("Waiting for the first report")
		case c.AutoRemediate && model.UnitRepairable(u):
			auto("The agent will turn on this installed user timer or service.")
		default:
			if strings.HasPrefix(i.Key, "unit:") {
				i.NextAction = "Check the unit on the machine."
			}
		}
	}
	return i
}
