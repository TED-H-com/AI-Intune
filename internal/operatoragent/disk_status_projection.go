package operatoragent

import (
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
)

// Status evidence is agent supplied. Only fixed categories and numeric fields
// cross MCP; free-form notes, mount names and protections become digests.
func redactedDiskStatus(s store.DiskOpsStatus) map[string]any {
	mounts := []any{}
	for _, m := range s.Mounts {
		mounts = append(mounts, map[string]any{"mount_digest": "sha256:" + scriptcatalog.Digest([]byte(m.Mount)), "total_bytes": m.TotalBytes, "available_bytes": m.AvailableBytes, "percent": m.Percent})
	}
	project := func(e *store.DiskSafeEnvelope) any {
		if e == nil {
			return nil
		}
		categories := map[string]any{}
		for _, name := range []string{"uv", "npm", "cargo", "docker", "journald", "user_tmp", "user_cache_tmp", "user_local_tmp", "var_tmp", "tool_caches"} {
			if c, ok := e.Summary.Categories[name]; ok {
				status := "unknown"
				switch c.Status {
				case "ok", "skipped", "error":
					status = c.Status
				}
				categories[name] = map[string]any{"status": status, "candidate_bytes": c.CandidateBytes, "freed_bytes": c.FreedBytes, "items": c.Items, "note_digest": "sha256:" + scriptcatalog.Digest([]byte(c.Note))}
			}
		}
		return map[string]any{"freed_bytes": e.Summary.FreedBytes, "categories": categories, "protections": pathProjection(e.Operation.Protections)}
	}
	ownership := map[string]string{}
	for _, scope := range []string{"user", "root"} {
		state := "unknown"
		switch s.Ownership[scope] {
		case "local-owned", "handoff-pending", "hub-owned", "rolled-back", "rollback-pending":
			state = s.Ownership[scope]
		}
		ownership[scope] = state
	}
	supervision := s.Supervision
	supervision.OwnershipStates = map[string]int{}
	for _, state := range []string{"local-owned", "handoff-pending", "hub-owned", "rolled-back", "rollback-pending"} {
		if n := s.Supervision.OwnershipStates[state]; n >= 0 {
			supervision.OwnershipStates[state] = n
		}
	}
	return map[string]any{"canary": func() map[string]any {
		v := map[string]any{}
		for _, scope := range []string{"user", "root"} {
			c := s.Canary[scope]
			v[scope] = map[string]any{"required_days": c.RequiredDays, "agreed_days": c.AgreedDays, "satisfied": c.Satisfied}
		}
		return v
	}(), "ignored_mounts": s.IgnoredMounts, "actions": s.Actions, "supervision": supervision, "machine_id": s.MachineID, "mounts": mounts, "thresholds": s.Thresholds, "last_safe_tier": project(s.LastSafeTier), "preview": project(s.Preview), "skip_count": len(s.Skips), "ownership": ownership, "writes_enabled": s.WritesEnabled}
}
