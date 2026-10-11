package main

import (
	"bytes"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"io"
	"net/http"
	"strings"
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
	writeJSON(w, 200, v)
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
	actor := operatorActor(r)
	action := store.AuditAction("schedule-run-now")
	if !h.requireAuditedJSON(w, r, actor, action) {
		return
	}
	var body struct{}
	if rejection := decodeOperatorBody(w, r, &body); rejection != nil {
		h.rejectOperatorPolicyTransport(w, r, actor, action, rejection.Status, rejection.Code, rejection.Detail)
		return
	}
	v, e := h.store.ScheduleGet(r.PathValue("id"))
	if e != nil {
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
	jobs, e := operator.New(h.store).ScheduleRunNow(v.ID, actor)
	if e != nil {
		writeSettingErr(w, "schedule", e)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]any{"job_ids": jobs})
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
