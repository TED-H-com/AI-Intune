package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
	"github.com/teddashh/AI-Intune/internal/store"
)

const errorBatchBytes = 256 * 1024

// The file credential grants only errors:read and is never an operator principal.
func (h *hub) errorRoutes(mux *http.ServeMux) []string {
	enabled, _ := strconv.ParseBool(os.Getenv("ERROR_INGEST_ENABLED"))
	token, err := os.ReadFile(os.Getenv("ERROR_READ_TOKEN_FILE"))
	secret := strings.TrimSpace(string(token))
	configured := err == nil && secret != ""
	hash := sha256.Sum256([]byte(secret))
	gate := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if !enabled {
				http.NotFound(w, r)
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("POST /api/v1/machines/{id}/errors", gate(h.authed(h.handleErrors)))
	read := gate(func(w http.ResponseWriter, r *http.Request) {
		bearer, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		candidate := sha256.Sum256([]byte(bearer))
		if !configured || !ok || subtle.ConstantTimeCompare(hash[:], candidate[:]) != 1 {
			writeErr(w, 401, "UNAUTHORIZED", "errors:read token required")
			return
		}
		since := time.Now().UTC().Add(-30 * 24 * time.Hour)
		if v := r.URL.Query().Get("since"); v != "" {
			var e error
			since, e = time.Parse(time.RFC3339Nano, v)
			if e != nil {
				writeErr(w, 400, "INVALID_SINCE", "since must be RFC3339")
				return
			}
		}
		var result any
		var e error
		if r.URL.Path == "/api/v1/errors/top" {
			result, e = h.store.TopErrors(r.Context(), since)
		} else {
			limit := 200
			if v := r.URL.Query().Get("limit"); v != "" {
				limit, e = strconv.Atoi(v)
				if e != nil || limit < 1 || limit > 1000 {
					writeErr(w, 400, "INVALID_LIMIT", "limit must be 1 to 1000")
					return
				}
			}
			result, e = h.store.ListErrors(r.Context(), store.ErrorFilter{Since: since, Component: r.URL.Query().Get("component"), Machine: r.URL.Query().Get("machine"), Limit: limit})
		}
		if e != nil {
			h.finishStoreError(w, "read errors", "", "internal error", e)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(result)
	})
	mux.HandleFunc("GET /api/v1/errors", read)
	mux.HandleFunc("GET /api/v1/errors/top", read)
	return []string{"POST /api/v1/machines/{id}/errors", "GET /api/v1/errors", "GET /api/v1/errors/top"}
}

func (h *hub) handleErrors(w http.ResponseWriter, r *http.Request, machine string) {
	if r.PathValue("id") != machine {
		writeErr(w, 403, "FORBIDDEN", "Machine credential does not match target")
		return
	}
	body, e := io.ReadAll(http.MaxBytesReader(w, r.Body, errorBatchBytes))
	if e != nil {
		writeErr(w, 413, "BATCH_TOO_LARGE", "Batch exceeds 256 KB")
		return
	}
	var records []errlog.Record
	if e = json.Unmarshal(body, &records); e != nil {
		writeErr(w, 400, "INVALID_BATCH", "JSON record array required")
		return
	}
	if len(records) > 200 {
		writeErr(w, 413, "BATCH_TOO_LARGE", "Batch exceeds 200 records")
		return
	}
	clean := make([]errlog.Record, 0, len(records))
	dropped := 0
	for _, record := range records {
		if record.MachineID != "" && record.MachineID != machine {
			writeErr(w, 403, "FORBIDDEN", "Record machine does not match credential")
			return
		}
		if record.TS.IsZero() || record.Component == "" || record.Code == "" || record.Fingerprint == "" || record.Count < 1 || record.Count > 1000000 || (record.Level != "warn" && record.Level != "error") {
			writeErr(w, 400, "INVALID_RECORD", "Record requires timestamp, component, code, fingerprint, level and count from 1 to 1000000")
			return
		}
		// Sanitize the entire serialized record, including context keys and metadata.
		raw, _ := json.Marshal(record)
		var value any
		json.Unmarshal(raw, &value)
		raw, _ = json.Marshal(redactErrorValue(value))
		redacted := string(raw)
		var safe errlog.Record
		if errlog.ContainsSecret(redacted) || json.Unmarshal([]byte(redacted), &safe) != nil {
			dropped++
			continue
		}
		safe.MachineID = machine
		raw, _ = json.Marshal(safe)
		if errlog.ContainsSecret(string(raw)) {
			dropped++
			continue
		}
		clean = append(clean, safe)
	}
	inserted, e := h.store.InsertErrors(r.Context(), clean)
	if e != nil {
		h.finishStoreError(w, "ingest errors", machine, "internal error", e)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"inserted": inserted, "dropped": dropped})
}

func redactErrorValue(v any) any {
	switch x := v.(type) {
	case string:
		return errlog.Redact(x)
	case []any:
		for i := range x {
			x[i] = redactErrorValue(x[i])
		}
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, value := range x {
			// Detect labeled credentials as well as secrets within string values.
			if errlog.ContainsSecret(k + "=credential") {
				out["[REDACTED]"] = "[REDACTED]"
			} else {
				out[errlog.Redact(k)] = redactErrorValue(value)
			}
		}
		return out
	default:
		return v
	}
}
