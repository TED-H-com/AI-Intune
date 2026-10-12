package main

import (
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strings"
)

func (h *hub) handleOperatorDiskActions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		if r.URL.RawQuery != "" {
			writeErr(w, 400, "BAD_REQUEST", "query not supported")
			return
		}
		items, err := h.retentionOperator().DiskQuarantineList(r.PathValue("machine_id"))
		if err != nil {
			writeSettingErr(w, "quarantine", err)
			return
		}
		writeJSON(w, 200, struct {
			Items []store.DiskQuarantineItem `json:"items"`
		}{items})
		return
	}
	actor := operatorActor(r)
	if !h.requireAuditedJSON(w, r, actor, store.AuditOpsApproval) || !h.requireDiskJSONFreshHuman(w, r, store.AuditOpsApproval) {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "query not supported")
		return
	}
	path := r.URL.Path
	var out any
	var err error
	if strings.HasSuffix(path, "/actions/preview") {
		var req store.DiskActionRequest
		if bad := decodeOperatorBody(w, r, &req); bad != nil {
			h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOpsApproval, bad.Status, bad.Code, bad.Detail)
			return
		}
		out, err = h.retentionOperator().DiskActionPreview(req, actor)
	} else if strings.HasSuffix(path, "/restores/preview") {
		var req store.DiskRestoreRequest
		if bad := decodeOperatorBody(w, r, &req); bad != nil {
			h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOpsApproval, bad.Status, bad.Code, bad.Detail)
			return
		}
		out, err = h.retentionOperator().DiskRestorePreview(req, actor)
	} else {
		var req store.OpsApprovalDecisionRequest
		if bad := decodeOperatorBody(w, r, &req); bad != nil {
			h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOpsApproval, bad.Status, bad.Code, bad.Detail)
			return
		}
		// A decision without a digest is the canonical read-only decision preview.
		apply := req.PreviewDigest != ""
		if strings.HasSuffix(path, "/restores") && req.Decision != "approved" {
			writeErr(w, 400, "BAD_REQUEST", "restore requires an approval")
			return
		}
		if strings.HasSuffix(path, "/restores") {
			out, err = h.retentionOperator().DiskRestoreApply(req, true, r.Header.Get("Idempotency-Key"), actor)
		} else {
			out, err = h.retentionOperator().DiskActionDecide(req, apply, r.Header.Get("Idempotency-Key"), actor)
		}
	}
	if err != nil {
		writeSettingErr(w, "disk action", err)
		return
	}
	if v, ok := out.(store.OpsApprovalDecisionResult); ok && v.Request.PreviewDigest != "" {
		writeDiskCleanResult(w, v.Replayed, v.Approval.JobID == "", v)
	} else {
		writeJSON(w, 200, out)
	}
}
