package operatoragent

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
)

// Only this allowlisted projection crosses MCP; full policy bodies stay on the
// human API/UI. Unknown or malformed client response shapes fail closed.
func redactedDiskPolicies(value any) (any, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, projectionError()
	}
	if len(raw) > 0 && raw[0] == '[' {
		var policies []store.OpsPolicy
		if err = json.Unmarshal(raw, &policies); err != nil {
			return nil, projectionError()
		}
		out := []any{}
		for _, p := range policies {
			item, e := redactedDiskPolicy(p)
			if e != nil {
				return nil, e
			}
			out = append(out, item)
		}
		return out, nil
	}
	var p store.OpsPolicy
	if err = json.Unmarshal(raw, &p); err != nil {
		return nil, projectionError()
	}
	return redactedDiskPolicy(p)
}
func projectionError() error {
	return &CallError{Code: "invalid_response", Message: "invalid disk policy response"}
}
func pathProjection(paths []string) any {
	digests := []string{}
	for _, p := range paths {
		digests = append(digests, "sha256:"+scriptcatalog.Digest([]byte(p)))
	}
	return map[string]any{"count": len(paths), "digests": digests}
}
func redactedDiskBody(raw json.RawMessage) (any, error) {
	p, _, _, err := store.CanonicalDiskPolicy(raw)
	if err != nil {
		return nil, projectionError()
	}
	return map[string]any{"schema_version": p.SchemaVersion, "safe_tier": p.SafeTier, "thresholds": p.Thresholds, "quarantine_ttl_days": p.QuarantineTTLDays, "scan_budgets": p.ScanBudgets, "protected_paths": pathProjection(p.ProtectPaths)}, nil
}
func redactedDiskPolicy(p store.OpsPolicy) (any, error) {
	body, err := redactedDiskBody(p.Body)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": p.ID, "kind": p.Kind, "revision": p.Revision, "digest": p.Digest, "created_by": p.CreatedBy, "created_at": p.CreatedAt, "superseded_at": p.SupersededAt, "body": body}, nil
}
func redactedDiskPolicyResult(r store.DiskPolicyResult) (any, error) {
	p, err := redactedDiskPolicy(r.Policy)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"policy": p, "expected_revision": r.ExpectedRevision, "expires_at": r.ExpiresAt, "preview_digest": r.PreviewDigest, "replayed": r.Replayed, "warnings": r.Warnings, "removed_protections": pathProjection(r.RemovedProtectPaths)}
	if len(r.PreviousBody) > 0 {
		previous, e := redactedDiskBody(r.PreviousBody)
		if e != nil {
			return nil, e
		}
		out["previous_body"] = previous
	}
	return out, nil
}
