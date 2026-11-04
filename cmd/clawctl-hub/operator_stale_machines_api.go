package main

import (
	"net/http"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func (h *hub) handleListOperatorStaleMachines(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || !principal.Has(operatorauth.View) {
		writeErr(w, http.StatusForbidden, "CAPABILITY_REQUIRED", "需要名冊讀取權限")
		return
	}
	if r.URL.ForceQuery || r.URL.RawQuery != "" {
		writeErr(w, http.StatusBadRequest, "BAD_REQUEST", "名冊整理不接受查詢參數")
		return
	}
	// Current operator view grants cover the whole Hub, including machine reads.
	result, err := h.controlPlaneService().ListStaleMachineCandidates(time.Now().UTC(), func(string) bool { return principal.Has(operatorauth.View) })
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "INTERNAL", "讀取名冊整理失敗")
		return
	}
	writeJSON(w, http.StatusOK, result)
}
