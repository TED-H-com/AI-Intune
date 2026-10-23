package main

import (
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strings"
)

func (h *hub) handleDiskOwnership(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		if r.URL.RawQuery != "" || r.URL.ForceQuery {
			writeErr(w, 400, "BAD_REQUEST", "query unsupported")
			return
		}
		v, e := h.retentionOperator().DiskOwnershipGet(r.PathValue("machine_id"), r.PathValue("scope"))
		if e != nil {
			writeSettingErr(w, "ownership", e)
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "query unsupported")
		return
	}
	actor := operatorActor(r)
	apply := !strings.HasSuffix(r.URL.Path, "/preview")
	if !h.requireAuditedJSON(w, r, actor, store.AuditAction("disk_ownership")) {
		return
	}
	if apply && !h.requireDiskJSONFreshHuman(w, r, store.AuditAction("disk_ownership")) {
		return
	}
	var req store.DiskOwnershipRequest
	if rejection := decodeOperatorBody(w, r, &req); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, store.AuditAction("disk_ownership"), rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	out, e := h.retentionOperator().DiskOwnershipManage(req, apply, r.Header.Get("Idempotency-Key"), actor)
	if e != nil {
		writeSettingErr(w, "ownership", e)
		return
	}
	if apply {
		writeDiskCleanResult(w, out.Replayed, false, out)
	} else {
		writeJSON(w, 200, out)
	}
}
func (h *hub) handleDiskAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "query unsupported")
		return
	}
	items, e := h.retentionOperator().DiskAlertsList("")
	if e != nil {
		writeSettingErr(w, "alerts", e)
		return
	}
	for i := range items {
		items[i].AcknowledgementReason = ""
	}
	// Condition identities contain digests, never private mount paths.
	writeJSON(w, 200, struct {
		Items []store.DiskAlert `json:"items"`
	}{items})
}

func (h *hub) handleDiskAlertAck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "query unsupported")
		return
	}
	actor := operatorActor(r)
	apply := !strings.HasSuffix(r.URL.Path, "/preview")
	if !h.requireAuditedJSON(w, r, actor, store.AuditAction("disk_alert_ack")) {
		return
	}
	if apply && !h.requireDiskJSONFreshHuman(w, r, store.AuditAction("disk_alert_ack")) {
		return
	}
	var req store.DiskAlertAckRequest
	if rejection := decodeOperatorBody(w, r, &req); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, store.AuditAction("disk_alert_ack"), rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	out, e := h.retentionOperator().DiskAlertAcknowledge(req, apply, r.Header.Get("Idempotency-Key"), actor)
	if e != nil {
		writeSettingErr(w, "alert acknowledgement", e)
		return
	}
	if apply {
		writeDiskCleanResult(w, out.Replayed, false, out)
	} else {
		writeJSON(w, 200, out)
	}
}
