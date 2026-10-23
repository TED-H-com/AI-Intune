package main

import (
	"net/http"
	"net/url"
)

func (h *hub) handleOperatorLoops(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(q) > 1 || len(q["machine_id"]) > 1 || r.URL.ForceQuery {
		writeErr(w, 400, "BAD_REQUEST", "invalid loop filter")
		return
	}
	for k := range q {
		if k != "machine_id" {
			writeErr(w, 400, "BAD_REQUEST", "invalid loop filter")
			return
		}
	}
	machine := q.Get("machine_id")
	if len(machine) > 256 {
		writeErr(w, 400, "BAD_REQUEST", "invalid machine filter")
		return
	}
	items, err := h.store.LoopEpisodes(machine)
	if err != nil {
		writeErr(w, 500, "STORE_ERROR", "unable to load loop episodes")
		return
	}
	policy, err := h.store.LoopPolicy()
	if err != nil {
		writeErr(w, 500, "STORE_ERROR", "unable to load loop policy")
		return
	}
	writeJSON(w, 200, map[string]any{"schema_version": 1, "policy": policy, "items": items, "limit": 200, "coverage": "agent_reported_call_activity_only"})
}
