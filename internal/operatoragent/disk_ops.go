package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
)

type diskPolicyHub interface {
	DiskPolicyRead(context.Context, string) (any, error)
	DiskPolicyUpsert(context.Context, store.DiskPolicyRequest, bool, string) (store.DiskPolicyResult, error)
}

func diskPolicyTools() []Tool {
	id := strField(1, 128, idPattern, "Policy ID")
	out := []Tool{{Name: "disk_policy_list", Description: "List disk policy revisions. Human view only; protected paths are represented by counts and digests.", InputSchema: obj(map[string]any{}), Annotations: readAnn("disk_policy_list")}, {Name: "disk_policy_get", Description: "Get latest disk policy revision. Human view only.", InputSchema: obj(map[string]any{"id": id}, "id"), Annotations: readAnn("disk_policy_get")}}
	for _, phase := range []string{"preview", "apply"} {
		name := "disk_policy_upsert_" + phase
		props := map[string]any{"id": id, "body": diskPolicySchema(), "expected_revision": intBound(0, 2147483647, "Current revision; zero for create"), "reason": strField(1, 500, "", "Reason without secrets")}
		required := []string{"id", "body", "expected_revision", "reason"}
		ann := readAnn(name)
		if phase == "apply" {
			props["preview_digest"] = strField(71, 71, digestPattern, "Matching preview digest")
			props["expires_at"] = strField(1, 64, "", "Preview expiry")
			props["acknowledge_removed_paths"] = map[string]any{"type": "array", "maxItems": 100, "uniqueItems": true, "items": strField(1, 1024, "^/", "Explicitly acknowledged removal from human preview")}
			props["idempotency_key"] = strField(1, 200, "", "Durable retry key")
			required = append(required, "preview_digest", "expires_at", "idempotency_key")
			ann = writeAnn(name, false)
		}
		out = append(out, Tool{Name: name, Description: "Upsert immutable disk policy. Requires human admin; apply requires disk_ops_v2_writes enabled.", InputSchema: obj(props, required...), Annotations: ann})
	}
	return out
}
func diskPolicySchema() map[string]any {
	return obj(map[string]any{
		"schema_version":      intBound(1, 1, ""),
		"safe_tier":           obj(map[string]any{"user_tmp_min_days": intBound(10, 3650, ""), "var_tmp_min_days": intBound(14, 3650, ""), "docker_min_hours": intBound(168, 87600, ""), "docker_mode": strEnum("dangling-and-build-cache"), "journald_max_mib": intBound(500, 1048576, ""), "cargo_min_days": intBound(30, 3650, ""), "uv_mode": strEnum("lock-aware-prune"), "npm_mode": strEnum("verify-only"), "tool_cache_mode": strEnum("native-gc-holder-aware")}, "user_tmp_min_days", "var_tmp_min_days", "docker_min_hours", "docker_mode", "journald_max_mib", "cargo_min_days", "uv_mode", "npm_mode", "tool_cache_mode"),
		"protect_paths":       map[string]any{"type": "array", "maxItems": 100, "uniqueItems": true, "items": strField(1, 1024, "^/", "Additional protected path")},
		"thresholds":          obj(map[string]any{"warn_percent": intBound(2, 99, ""), "critical_percent": intBound(3, 100, ""), "deep_report_above_percent": intBound(1, 98, "Strictly greater than trigger")}, "warn_percent", "critical_percent", "deep_report_above_percent"),
		"quarantine_ttl_days": intBound(7, 7, ""),
		"scan_budgets":        obj(map[string]any{"max_items": intBound(1, 500, ""), "max_entries": intBound(1, 200000, ""), "max_seconds": intBound(1, 600, "")}, "max_items", "max_entries", "max_seconds"),
	}, "schema_version", "safe_tier", "protect_paths", "thresholds", "quarantine_ttl_days", "scan_budgets")
}
func (s *Service) diskPolicyCall(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	h, ok := s.Hub.(diskPolicyHub)
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "disk policy client unavailable"}
	}
	if name == "disk_policy_list" {
		if e := decodeEmpty(raw); e != nil {
			return nil, e
		}
		v, e := h.DiskPolicyRead(ctx, "")
		if e != nil {
			return nil, hubErr(e)
		}
		return redactedDiskPolicies(v)
	}
	if name == "disk_policy_get" {
		var req struct {
			ID string `json:"id"`
		}
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		if req.ID == "" {
			return nil, &CallError{Code: "invalid_arguments", Message: "id required"}
		}
		v, e := h.DiskPolicyRead(ctx, req.ID)
		if e != nil {
			return nil, hubErr(e)
		}
		return redactedDiskPolicies(v)
	}
	var req struct {
		store.DiskPolicyRequest
		IdempotencyKey string `json:"idempotency_key"`
	}
	if e := decodeArgs(raw, &req); e != nil {
		return nil, e
	}
	apply := strings.HasSuffix(name, "_apply")
	if apply {
		if e := requireIdempotency(req.IdempotencyKey); e != nil {
			return nil, e
		}
		if e := requireDigest(req.PreviewDigest); e != nil {
			return nil, e
		}
	} else if req.PreviewDigest != "" || req.IdempotencyKey != "" || !req.ExpiresAt.IsZero() {
		return nil, &CallError{Code: "invalid_arguments", Message: "preview does not accept apply bindings"}
	}
	v, e := h.DiskPolicyUpsert(ctx, req.DiskPolicyRequest, apply, req.IdempotencyKey)
	if e != nil {
		return nil, hubErr(e)
	}
	return redactedDiskPolicyResult(v)
}
