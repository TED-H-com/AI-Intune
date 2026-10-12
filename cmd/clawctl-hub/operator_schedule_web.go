package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
)

// Inspect only bounded form identity fields, replaying the body unchanged for
// the strict HTML adapter. Stored mode also gates edits away from write scripts.
func scheduleWebPermission(r *http.Request, st *store.Store) operatorauth.Permission {
	var id, script string
	if strings.HasSuffix(r.URL.Path, "/run-now") {
		parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
		if len(parts) == 4 {
			id = parts[2]
		}
	}
	if r.Body != nil {
		original := r.Body
		prefix, err := io.ReadAll(io.LimitReader(original, (64<<10)+1))
		r.Body = scriptReplayBody{Reader: io.MultiReader(bytes.NewReader(prefix), original), Closer: original}
		if err != nil || len(prefix) > 64<<10 {
			return operatorauth.Admin
		}
		form, err := url.ParseQuery(string(prefix))
		if err == nil {
			if id == "" {
				id = form.Get("id")
			}
			script = form.Get("script_id")
			if raw := form.Get("request"); raw != "" {
				var req store.ScheduleRequest
				if json.Unmarshal([]byte(raw), &req) == nil {
					id = req.ID
					script = req.ScriptID
				}
			}
		}
	}
	if e, ok := scriptcatalog.Lookup(script); ok && e.Mode == "write" {
		return operatorauth.Admin
	}
	if st != nil && id != "" {
		if v, err := st.ScheduleGet(id); err == nil {
			if e, ok := scriptcatalog.Lookup(v.ScriptID); ok && e.Mode == "write" {
				return operatorauth.Admin
			}
		}
	}
	return operatorauth.Operate
}
