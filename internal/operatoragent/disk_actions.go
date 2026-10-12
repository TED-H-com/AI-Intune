package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/store"
)

type diskActionsHub interface {
	DiskActionPreview(context.Context, store.DiskActionRequest) (store.DiskActionPreview, error)
	DiskRestorePreview(context.Context, store.DiskRestoreRequest) (store.DiskActionPreview, error)
	DiskActionDecide(context.Context, store.OpsApprovalDecisionRequest, string, bool) (store.OpsApprovalDecisionResult, error)
	DiskQuarantineList(context.Context, string) ([]store.DiskQuarantineItem, error)
}

func diskActionTools() []Tool {
	id := strField(1, 128, idPattern, "Evidence ID")
	ids := map[string]any{"type": "array", "minItems": 1, "maxItems": 100, "uniqueItems": true, "items": id}
	common := map[string]any{"id": id, "decision": strEnum("approved", "rejected"), "policy_revision": intBound(1, 2147483647, "Exact revision"), "policy_digest": strField(71, 71, digestPattern, "Digest"), "item_digest": strField(71, 71, digestPattern, "Manifest digest"), "deadline": strField(1, 64, "", "Deadline"), "preview_digest": strField(71, 71, digestPattern, "Decision preview; omit to preview"), "reason": strField(1, 500, "", "Human reason"), "idempotency_key": strField(1, 200, "", "Retry key")}
	return []Tool{
		{Name: "disk_action_preview", Description: "Preview quarantine or separately approved irreversible delete. Fresh human admin only; no delegation.", InputSchema: obj(map[string]any{"report_id": id, "report_digest": strField(71, 71, digestPattern, "Report digest"), "action": strEnum("quarantine", "delete", "reject"), "item_ids": ids, "reason": strField(1, 500, "", "Human reason")}, "report_id", "report_digest", "action", "item_ids", "reason"), Annotations: writeAnn("disk_action_preview", false)},
		{Name: "disk_action_decide", Description: "Preview a decision, or consume exact approval once with job creation. Fresh human admin only.", InputSchema: obj(common, "id", "decision", "reason"), Annotations: writeAnn("disk_action_decide", false)},
		{Name: "disk_quarantine_list", Description: "Read scrubbed quarantine items and expiry countdown. Requires view.", InputSchema: obj(map[string]any{"machine_id": id}, "machine_id"), Annotations: readAnn("disk_quarantine_list")},
		{Name: "disk_restore_preview", Description: "Preview exact restore. Fresh human admin only; never delegated.", InputSchema: obj(map[string]any{"quarantine_id": id, "item_ids": ids, "reason": strField(1, 500, "", "Human reason")}, "quarantine_id", "item_ids", "reason"), Annotations: writeAnn("disk_restore_preview", false)},
		{Name: "disk_restore_apply", Description: "Consume a separately reviewed restore approval. Fresh human admin only; never overwrite.", InputSchema: obj(common, "id", "decision", "reason"), Annotations: writeAnn("disk_restore_apply", false)},
	}
}
func (s *Service) diskActionCall(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	h, ok := s.Hub.(diskActionsHub)
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "disk action client unavailable"}
	}
	switch name {
	case "disk_quarantine_list":
		var req struct {
			Machine string `json:"machine_id"`
		}
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		v, e := h.DiskQuarantineList(ctx, req.Machine)
		for i := range v {
			v[i].DisplayPath = diskreport.PublicItem(diskreport.Item{DisplayPath: v[i].DisplayPath}).DisplayPath
		}
		return v, hubErr(e)
	case "disk_action_preview":
		var req store.DiskActionRequest
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		v, e := h.DiskActionPreview(ctx, req)
		for i := range v.Items {
			v.Items[i] = diskreport.PublicItem(v.Items[i])
		}
		return v, hubErr(e)
	case "disk_restore_preview":
		var req store.DiskRestoreRequest
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		v, e := h.DiskRestorePreview(ctx, req)
		for i := range v.Items {
			v.Items[i] = diskreport.PublicItem(v.Items[i])
		}
		return v, hubErr(e)
	default:
		var req struct {
			store.OpsApprovalDecisionRequest
			Key string `json:"idempotency_key"`
		}
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		if req.PreviewDigest != "" {
			if e := requireIdempotency(req.Key); e != nil {
				return nil, e
			}
			if e := requireDigest(req.PreviewDigest); e != nil {
				return nil, e
			}
		}
		if name == "disk_restore_apply" && (req.PreviewDigest == "" || req.Decision != "approved") {
			return nil, &CallError{Code: "invalid_arguments", Message: "restore apply requires exact approval bindings"}
		}
		v, e := h.DiskActionDecide(ctx, req.OpsApprovalDecisionRequest, req.Key, name == "disk_restore_apply")
		return v, hubErr(e)
	}
}
