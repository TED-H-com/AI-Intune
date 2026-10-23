package main

import (
	"encoding/json"
	"net/http"
)

// handleVersion exposes build provenance only, never runtime configuration.
func handleVersion(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(struct {
		Version   string `json:"version"`
		Commit    string `json:"commit"`
		BuildTime string `json:"build_time"`
	}{version, commit, buildTime})
}
