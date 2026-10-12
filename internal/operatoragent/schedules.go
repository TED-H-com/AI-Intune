package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
)

type scheduleHub interface {
	ScheduleRead(context.Context, string) (any, error)
	ScheduleManage(context.Context, store.ScheduleRequest, string, bool, string) (store.ScheduleResult, error)
	ScheduleRunNow(context.Context, string, string) (any, error)
}

func scheduleTools() []Tool {
	props := map[string]any{"id": strField(1, 128, idPattern, "Schedule ID"), "name": strField(1, 63, "^[a-z0-9][a-z0-9-]*$", "Unique name"), "script_id": strField(1, 128, idPattern, "Catalog ID"), "script_sha256": strField(64, 64, "^[a-f0-9]{64}$", "Approved hash"), "args": map[string]any{"type": "object"}, "targets": map[string]any{"type": "array", "minItems": 1, "maxItems": 50, "uniqueItems": true, "items": strField(1, 128, idPattern, "")}, "cron": strField(1, 128, "", "Five numeric fields in tz (default UTC); minimum five minutes"), "tz": strField(1, 128, "", "IANA timezone; optional, default UTC"), "enabled": map[string]any{"type": "boolean"}, "catch_up": map[string]any{"type": "boolean", "enum": []bool{false}}, "expected_revision": intBound(0, 2147483647, "Current revision; zero for create"), "reason": strField(1, 500, "", "Reason without credentials")}
	out := []Tool{{Name: "schedule_list", Description: "List schedules. Requires view.", InputSchema: obj(map[string]any{}), Annotations: readAnn("schedule_list")}, {Name: "schedule_get", Description: "Get a schedule. Requires view.", InputSchema: obj(map[string]any{"id": props["id"]}, "id"), Annotations: readAnn("schedule_get")}, {Name: "schedule_run_now", Description: "Run an approved schedule now, with overlap protection. Requires operate for read scripts, admin for write scripts.", InputSchema: obj(map[string]any{"id": props["id"], "idempotency_key": strField(1, 200, "", "Durable manual run key")}, "id", "idempotency_key"), Annotations: writeAnn("schedule_run_now", false)}}
	for _, op := range []string{"upsert", "set_enabled"} {
		for _, phase := range []string{"preview", "apply"} {
			p := map[string]any{}
			for k, v := range props {
				if op == "upsert" || k == "id" || k == "enabled" || k == "expected_revision" || k == "reason" {
					p[k] = v
				}
			}
			required := []string{"enabled", "expected_revision", "reason"}
			if op == "upsert" {
				required = append(required, "name", "script_id", "script_sha256", "args", "targets", "cron")
			} else {
				required = append(required, "id")
			}
			name := "schedule_" + op + "_" + phase
			ann := readAnn(name)
			if phase == "apply" {
				p["preview_digest"] = strField(71, 71, digestPattern, "Matching preview digest")
				p["idempotency_key"] = strField(1, 200, "", "Idempotency key")
				required = append(required, "preview_digest", "idempotency_key")
				ann = writeAnn(name, false)
			}
			out = append(out, Tool{Name: name, Description: "Manage schedule. Requires operate for read scripts, admin for write scripts.", InputSchema: obj(p, required...), Annotations: ann})
		}
	}
	return out
}
func (s *Service) scheduleCall(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	h, ok := s.Hub.(scheduleHub)
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "schedule client unavailable"}
	}
	if name == "schedule_list" {
		if e := decodeEmpty(raw); e != nil {
			return nil, e
		}
		v, e := h.ScheduleRead(ctx, "")
		return v, hubErr(e)
	}
	if name == "schedule_get" || name == "schedule_run_now" {
		var req struct {
			ID             string `json:"id"`
			IdempotencyKey string `json:"idempotency_key"`
		}
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		if req.ID == "" {
			return nil, &CallError{Code: "invalid_arguments", Message: "id required"}
		}
		if name == "schedule_get" {
			if req.IdempotencyKey != "" {
				return nil, &CallError{Code: "invalid_arguments", Message: "schedule_get does not accept idempotency_key"}
			}
			v, e := h.ScheduleRead(ctx, req.ID)
			return v, hubErr(e)
		}
		if e := requireIdempotency(req.IdempotencyKey); e != nil {
			return nil, e
		}
		v, e := h.ScheduleRunNow(ctx, req.ID, req.IdempotencyKey)
		return v, hubErr(e)
	}
	var req struct {
		store.ScheduleRequest
		IdempotencyKey string `json:"idempotency_key"`
	}
	if e := decodeArgs(raw, &req); e != nil {
		return nil, e
	}
	apply := strings.HasSuffix(name, "_apply")
	if apply {
		if e := requireDigest(req.PreviewDigest); e != nil {
			return nil, e
		}
		if e := requireIdempotency(req.IdempotencyKey); e != nil {
			return nil, e
		}
	} else if req.PreviewDigest != "" || req.IdempotencyKey != "" {
		return nil, &CallError{Code: "invalid_arguments", Message: "preview does not accept apply coordinates"}
	}
	op := "upsert"
	if strings.Contains(name, "set_enabled") {
		op = "set-enabled"
	}
	v, e := h.ScheduleManage(ctx, req.ScheduleRequest, op, apply, req.IdempotencyKey)
	return v, hubErr(e)
}
