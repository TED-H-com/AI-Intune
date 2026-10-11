package main

import (
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strings"
	"time"
)

func (h *hub) handleDiskPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "query parameters are not supported")
		return
	}
	svc := h.retentionOperator()
	if r.Method == http.MethodGet {
		var result any
		var err error
		if r.PathValue("id") != "" {
			result, err = svc.DiskPolicy(r.PathValue("id"))
		} else {
			var items []store.OpsPolicy
			items, err = svc.DiskPolicies()
			result = struct {
				Items []store.OpsPolicy `json:"items"`
			}{items}
		}
		if err != nil {
			writeSettingErr(w, "disk policies", err)
			return
		}
		writeJSON(w, 200, result)
		return
	}
	actor := operatorActor(r)
	if !h.requireAuditedJSON(w, r, actor, store.AuditDiskPolicyApply) {
		return
	}
	apply := r.URL.Path == "/v1/operator/disk-ops/policies"
	if apply && !h.requireDiskJSONFreshHuman(w, r, store.AuditDiskPolicyApply) {
		return
	}
	var req store.DiskPolicyRequest
	if rejection := decodeOperatorBody(w, r, &req); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, store.AuditDiskPolicyApply, rejection.Status, rejection.Code, rejection.Detail)
		return
	}

	out, err := svc.DiskPolicyUpsert(req, apply, r.Header.Get("Idempotency-Key"), actor)
	if err != nil {
		writeSettingErr(w, "disk policy", err)
		return
	}
	if apply {
		writeDiskCleanResult(w, out.Replayed, false, out)
	} else {
		writeJSON(w, 200, out)
	}
}
func (h *hub) handleDiskOpsApprovals(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	for k, v := range r.URL.Query() {
		if (k != "state" && k != "machine_id" && k != "operation") || len(v) != 1 {
			writeErr(w, 400, "BAD_REQUEST", "invalid approval filters")
			return
		}
	}
	q := r.URL.Query()
	items, err := h.retentionOperator().DiskOpsApprovalsFiltered(q.Get("state"), q.Get("machine_id"), q.Get("operation"), time.Now().UTC())
	if err != nil {
		writeSettingErr(w, "disk approvals", err)
		return
	}
	writeJSON(w, 200, struct {
		Items []store.OpsApproval `json:"items"`
	}{items})
}

func (h *hub) handleDiskApprovalDecision(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor := operatorActor(r)
	if !h.requireAuditedJSON(w, r, actor, store.AuditOpsApproval) {
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/preview") && !h.requireDiskJSONFreshHuman(w, r, store.AuditOpsApproval) {
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOpsApproval, 400, "BAD_REQUEST", "decision does not accept query parameters")
		return
	}
	var req store.OpsApprovalDecisionRequest
	if rejection := decodeOperatorBody(w, r, &req); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOpsApproval, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	if req.ID != "" && req.ID != r.PathValue("id") {
		h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOpsApproval, 400, "BAD_REQUEST", "approval ID mismatch")
		return
	}
	req.ID = r.PathValue("id")
	out, err := h.retentionOperator().DiskOpsApprovalDecision(req, !strings.HasSuffix(r.URL.Path, "/preview"), r.Header.Get("Idempotency-Key"), actor)
	if err != nil {
		writeSettingErr(w, "disk approval decision", err)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/preview") {
		writeDiskCleanResult(w, out.Replayed, false, out)
	} else {
		writeJSON(w, 200, out)
	}
}

// Local sessions have no action-bound JSON reauthentication proof. Only the
// boundary's fresh human LocalAPI authorization can admit JSON applies.
func (h *hub) requireDiskJSONFreshHuman(w http.ResponseWriter, r *http.Request, action store.AuditAction) bool {
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	if ok && p.AuthMethod == operatorauth.AuthMethodLocalAPI && p.Has(operatorauth.Admin) && p.StableSubject() != "" {
		return true
	}
	h.rejectOperatorPolicyTransport(w, r, operatorActor(r), action, 403, "FORBIDDEN", "JSON apply requires fresh human authorization; local-account users must apply through the reauthenticated Hub UI")
	return false
}
