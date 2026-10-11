package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"io"
	"net/http"
	"strings"
	"time"
)

func (h *hub) handleScheduleList(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeErr(w, 400, "BAD_REQUEST", "query unsupported")
		return
	}
	v, e := h.store.ScheduleList()
	if e != nil {
		writeSettingErr(w, "schedules", e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, store.ScheduleListResponse{Items: v})
}
func (h *hub) handleScheduleGet(w http.ResponseWriter, r *http.Request) {
	v, e := h.store.ScheduleGet(r.PathValue("id"))
	if e != nil {
		writeErr(w, 404, "NOT_FOUND", "schedule not found")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, v)
}
func (h *hub) handleScheduleManage(w http.ResponseWriter, r *http.Request) {
	if !h.admitScheduleMutation(w, r) {
		return
	}
	actor := operatorActor(r)
	op := r.PathValue("operation")
	phase := r.PathValue("phase")
	apply := phase == "apply"
	if (op != "upsert" && op != "set-enabled") || (phase != "preview" && !apply) {
		writeErr(w, 404, "NOT_FOUND", "unknown operation")
		return
	}
	action := store.AuditAction("schedule-" + op + "-" + phase)
	if !h.requireAuditedJSON(w, r, actor, action) {
		return
	}
	if p, ok := operatorauth.PrincipalFromContext(r.Context()); apply && ok && p.Has(operatorauth.Admin) && !h.requireDiskJSONFreshHuman(w, r, action) {
		return
	}
	var body store.ScheduleRequest
	if rejection := decodeOperatorBody(w, r, &body); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, action, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	script := body.ScriptID
	if body.ID != "" {
		v, e := h.store.ScheduleGet(body.ID)
		if e == nil {
			entry, _ := scriptcatalog.Lookup(v.ScriptID)
			if entry.Mode == "write" {
				script = v.ScriptID
			}
		}
	}
	entry, _ := scriptcatalog.Lookup(script)
	if entry.Mode == "write" {
		p, ok := operatorauth.PrincipalFromContext(r.Context())
		if !ok || !p.Has(operatorauth.Admin) {
			h.rejectOperatorPolicyTransport(w, r, actor, action, 403, "SCRIPT_SCOPE_REQUIRED", "write scripts require admin")
			return
		}
		actor.AuthCapability = p.GrantedCapabilities.Admin
	}
	result, e := operator.New(h.store).ScheduleManage(body, op, apply, r.Header.Get("Idempotency-Key"), actor)
	if e != nil {
		writeSettingErr(w, "schedule", e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if apply {
		writeDiskCleanResult(w, result.Replayed, false, result)
	} else {
		writeJSON(w, 200, result)
	}
}
func (h *hub) handleScheduleRunNow(w http.ResponseWriter, r *http.Request) {
	if !h.admitScheduleMutation(w, r) {
		return
	}
	actor := operatorActor(r)
	action := store.AuditAction("schedule-run-now")
	if !h.requireAuditedJSON(w, r, actor, action) {
		return
	}
	if p, ok := operatorauth.PrincipalFromContext(r.Context()); ok && p.Has(operatorauth.Admin) && !h.requireDiskJSONFreshHuman(w, r, action) {
		return
	}
	var body struct{}
	if rejection := decodeOperatorBody(w, r, &body); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, action, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	v, e := h.store.ScheduleGet(r.PathValue("id"))
	if e != nil {
		if !errors.Is(e, sql.ErrNoRows) {
			writeSettingErr(w, "schedule", e)
			return
		}
		if e = operator.New(h.store).RejectScheduleRunNow(r.PathValue("id"), r.Header.Get("Idempotency-Key"), actor); e != nil {
			writeSettingErr(w, "schedule audit", e)
			return
		}
		writeErr(w, 404, "NOT_FOUND", "schedule not found")
		return
	}

	entry, _ := scriptcatalog.Lookup(v.ScriptID)
	if entry.Mode == "write" {
		p, ok := operatorauth.PrincipalFromContext(r.Context())
		if !ok || !p.Has(operatorauth.Admin) {
			h.rejectOperatorPolicyTransport(w, r, actor, action, 403, "SCRIPT_SCOPE_REQUIRED", "write scripts require admin")
			return
		}
		actor.AuthCapability = p.GrantedCapabilities.Admin
	}
	result, e := operator.New(h.store).ScheduleRunNow(v.ID, r.Header.Get("Idempotency-Key"), actor)
	if e != nil {
		writeSettingErr(w, "schedule", e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	if result.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	writeJSON(w, 200, result)
}

// The registry and stored schedule select the boundary scope, never a caller mode.
func scheduleRequestPermission(r *http.Request, st *store.Store) operatorauth.Permission {
	var id, script string
	if strings.HasSuffix(r.URL.Path, "/run-now") {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 5 {
			id = parts[3]
		}
	} else if r.Body != nil {
		original := r.Body
		prefix, e := io.ReadAll(io.LimitReader(original, (64<<10)+1))
		r.Body = scriptReplayBody{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original}
		if e != nil || len(prefix) > 64<<10 {
			return operatorauth.Admin
		}
		var req struct {
			ID       string `json:"id"`
			ScriptID string `json:"script_id"`
		}
		if json.Unmarshal(prefix, &req) != nil {
			return operatorauth.Operate
		}
		id = req.ID
		script = req.ScriptID
	}
	if entry, ok := scriptcatalog.Lookup(script); ok && entry.Mode == "write" {
		return operatorauth.Admin
	}
	if id != "" && st != nil {
		v, e := st.ScheduleGet(id)
		if e == nil {
			if entry, ok := scriptcatalog.Lookup(v.ScriptID); ok && entry.Mode == "write" {
				return operatorauth.Admin
			}
		}
	}
	return operatorauth.Operate
}

func (h *hub) admitScheduleMutation(w http.ResponseWriter, r *http.Request) bool {
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || p.StableSubject() == "" {
		writeErr(w, 403, "SCRIPT_SCOPE_REQUIRED", "authenticated script principal required")
		return false
	}
	if !h.scriptRunLimiter.allow(p.StableSubject(), time.Now()) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Retry-After", "2")
		writeErr(w, 429, "RATE_LIMITED", "script request rate limit exceeded; retry shortly")
		return false
	}
	return true
}
