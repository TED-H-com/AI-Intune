package main

import (
	"net/http"
	"strings"

	"github.com/teddashh/AI-Intune/internal/store"
)

func (h *hub) handleOfflineAlertSettings(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	actor := operatorActor(r)
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "query parameters not supported")
		return
	}
	svc := h.operatorReportService()
	if r.Method == http.MethodGet {
		out, err := svc.OfflineAlertSettings()
		if err != nil {
			writeSettingErr(w, "offline alerts", err)
			return
		}
		writeJSON(w, 200, out)
		return
	}
	if !h.requireAuditedJSON(w, r, actor, store.AuditOfflineAlertSettings) {
		return
	}
	apply := !strings.HasSuffix(r.URL.Path, "/preview")
	var req store.OfflineAlertSettingsRequest
	if apply {
		if rejection := decodeOperatorBody(w, r, &req); rejection != nil {
			h.rejectOperatorPolicyTransport(w, r, actor, store.AuditOfflineAlertSettings, rejection.Status, rejection.Code, rejection.Detail)
			return
		}
		out, err := svc.ApplyOfflineAlertSettings(req, r.Header.Get("Idempotency-Key"), actor)
		if err != nil {
			writeSettingErr(w, "offline alerts", err)
			return
		}
		if out.Replayed {
			w.Header().Set("Idempotency-Replayed", "true")
		}
		writeJSON(w, 200, out)
	} else {
		var body struct {
			Minutes int `json:"minutes"`
		}
		if rejection := decodeOperatorBody(w, r, &body); rejection != nil {
			writeErr(w, rejection.Status, rejection.Code, rejection.Detail)
			return
		}
		out, err := svc.PreviewOfflineAlertSettings(body.Minutes)
		if err != nil {
			writeSettingErr(w, "offline alerts", err)
			return
		}
		writeJSON(w, 200, out)
	}
}
