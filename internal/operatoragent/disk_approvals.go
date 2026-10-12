package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
)

type diskApprovalHub interface {
	DiskApprovalList(context.Context, string, string, string) ([]store.OpsApproval, error)
	DiskApprovalDecision(context.Context, store.OpsApprovalDecisionRequest, bool, string) (store.OpsApprovalDecisionResult, error)
}

func diskApprovalTools() []Tool {
	out := []Tool{{Name: "disk_approval_list", Description: "Read disk approval ledger. Optional client; the same ledger is available in the Hub UI. Requires view.", InputSchema: obj(map[string]any{"state": strEnum("pending", "approved", "rejected", "expired", "consumed"), "machine_id": strField(1, 128, idPattern, "Machine ID"), "operation": strEnum("quarantine", "delete", "restore", "safe-clean")}), Annotations: readAnn("disk_approval_list")}}
	for _, phase := range []string{"preview", "apply"} {
		name := "disk_approval_decision_" + phase
		p := map[string]any{"id": strField(1, 128, idPattern, "Approval ID"), "decision": strEnum("approved", "rejected"), "reason": strField(1, 500, "", "Human decision reason")}
		required := []string{"id", "decision", "reason"}
		ann := readAnn(name)
		if phase == "apply" {
			p["policy_revision"] = intBound(1, 2147483647, "Preview policy revision")
			p["policy_digest"] = strField(71, 71, digestPattern, "Preview policy digest")
			p["item_digest"] = strField(71, 71, digestPattern, "Preview item digest")
			p["deadline"] = strField(1, 64, "", "Original approval deadline")
			p["preview_digest"] = strField(71, 71, digestPattern, "Matching preview digest")
			p["idempotency_key"] = strField(1, 200, "", "Durable retry key")
			required = append(required, "policy_revision", "policy_digest", "item_digest", "deadline", "preview_digest", "idempotency_key")
			ann = writeAnn(name, false)
		}
		out = append(out, Tool{Name: name, Description: "Preview or apply a disk approval decision. Human admin only, never service tokens; also available in Hub UI.", InputSchema: obj(p, required...), Annotations: ann})
	}
	return out
}
func (s *Service) diskApprovalCall(ctx context.Context, name string, raw json.RawMessage) (any, error) {
	h, ok := s.Hub.(diskApprovalHub)
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "disk approval client unavailable"}
	}
	if name == "disk_approval_list" {
		var req struct {
			State     string `json:"state"`
			Machine   string `json:"machine_id"`
			Operation string `json:"operation"`
		}
		if e := decodeArgs(raw, &req); e != nil {
			return nil, e
		}
		v, e := h.DiskApprovalList(ctx, req.State, req.Machine, req.Operation)
		return v, hubErr(e)
	}
	var req struct {
		store.OpsApprovalDecisionRequest
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
	}
	v, e := h.DiskApprovalDecision(ctx, req.OpsApprovalDecisionRequest, apply, req.IdempotencyKey)
	return v, hubErr(e)
}
