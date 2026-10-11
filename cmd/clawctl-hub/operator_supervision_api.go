package main

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func parseSupervisionQuery(r *http.Request, jobs bool) (operator.SupervisionFilter, error) {
	f := operator.SupervisionFilter{}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return f, operator.ErrInvalidSupervision
	}
	for key := range values {
		if key != "window" && (!jobs || (key != "kind" && key != "machine_id" && key != "per_machine")) {
			return f, operator.ErrInvalidSupervision
		}
		v, e := oneOperatorAuditQueryValue(values, key, 256)
		if e != nil {
			return f, operator.ErrInvalidSupervision
		}
		switch key {
		case "window":
			f.Window = v
		case "kind":
			f.Kind = v
		case "machine_id":
			f.MachineID = v
		case "per_machine":
			if v != "true" && v != "false" {
				return f, operator.ErrInvalidSupervision
			}
			f.PerMachine = v == "true"
		}
	}
	if r.URL.ForceQuery && r.URL.RawQuery == "" {
		return f, operator.ErrInvalidSupervision
	}
	return f, operator.ValidateSupervisionFilter(f)
}

func (h *hub) handleOperatorJobsSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	f, err := parseSupervisionQuery(r, true)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid supervision filter")
		return
	}
	subject, ok := supervisionSubject(w, r)
	if !ok {
		return
	}
	result, err := h.supervisionService().JobsSummary(r.Context(), subject, f)
	if err != nil {
		writeSupervisionError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (h *hub) handleOperatorApprovalsSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	f, err := parseSupervisionQuery(r, false)
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid supervision filter")
		return
	}
	subject, ok := supervisionSubject(w, r)
	if !ok {
		return
	}
	result, err := h.supervisionService().ApprovalsSummary(r.Context(), subject, f.Window)
	if err != nil {
		writeSupervisionError(w, err)
		return
	}
	writeJSON(w, 200, result)
}
func (h *hub) handleOperatorHubStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "hub status accepts no query")
		return
	}
	subject, ok := supervisionSubject(w, r)
	if !ok {
		return
	}
	result, err := h.supervisionService().HubStatus(r.Context(), subject)
	if err != nil {
		writeSupervisionError(w, err)
		return
	}
	writeJSON(w, 200, result)
}

func (h *hub) supervisionService() *operator.SupervisionService {
	h.supervisionOnce.Do(func() { h.supervision = operator.NewSupervisionService(operator.New(h.store), version, h.startedAt) })
	return h.supervision
}
func supervisionSubject(w http.ResponseWriter, r *http.Request) (string, bool) {
	principal, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || principal.StableSubject() == "" {
		writeErr(w, http.StatusForbidden, "AUTH_REQUIRED", "authenticated supervision subject required")
		return "", false
	}
	return principal.StableSubject(), true
}
func writeSupervisionError(w http.ResponseWriter, err error) {
	if errors.Is(err, operator.ErrSupervisionRateLimited) || errors.Is(err, operator.ErrSupervisionBusy) {
		w.Header().Set("Retry-After", "2")
		code := "SUPERVISION_BUSY"
		if errors.Is(err, operator.ErrSupervisionRateLimited) {
			code = "SUPERVISION_RATE_LIMITED"
		}
		writeErr(w, http.StatusTooManyRequests, code, "supervision temporarily throttled")
		return
	}
	writeErr(w, http.StatusInternalServerError, "INTERNAL", "supervision read failed")
}
