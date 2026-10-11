package main

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/store"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

func (h *hub) handleDiskReportUpload(w http.ResponseWriter, r *http.Request, machine string) {
	w.Header().Set("Cache-Control", "no-store")
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" {
		writeErr(w, 400, "BAD_REQUEST", "JSON body required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 96<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	var out diskreport.Receipt
	if strings.HasSuffix(r.URL.Path, "/chunks") {
		var req diskreport.Chunk
		err = d.Decode(&req)
		if err != nil {
			writeErr(w, 400, "BAD_REQUEST", "invalid report body")
			return
		}
		if err == nil && d.Decode(new(any)) != io.EOF {
			writeErr(w, 400, "BAD_REQUEST", "invalid report body")
			return
		}
		if err == nil {
			out, err = h.store.DiskReportChunk(machine, r.PathValue("job_id"), req)
		}
	} else {
		var req diskreport.Complete
		err = d.Decode(&req)
		if err != nil {
			writeErr(w, 400, "BAD_REQUEST", "invalid report body")
			return
		}
		if err == nil && d.Decode(new(any)) != io.EOF {
			writeErr(w, 400, "BAD_REQUEST", "invalid report body")
			return
		}
		if err == nil {
			out, err = h.store.DiskReportComplete(machine, r.PathValue("job_id"), req)
		}
	}
	if err != nil {
		writeSettingErr(w, "disk report upload", err)
		return
	}
	writeJSON(w, 200, out)
}
func (h *hub) handleDiskReports(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	q := r.URL.Query()
	id := r.PathValue("id")
	for key, v := range q {
		if len(v) != 1 || (id == "" && key != "machine_id") || (id != "" && key != "cursor" && key != "limit") {
			writeErr(w, 400, "BAD_REQUEST", "invalid report query")
			return
		}
	}
	svc := h.retentionOperator()
	if id == "" {
		items, err := svc.DiskReports(q.Get("machine_id"))
		if err != nil {
			writeSettingErr(w, "disk reports", err)
			return
		}
		writeJSON(w, 200, struct {
			Items []store.DiskReportSummary `json:"items"`
		}{items})
		return
	}
	limit := 100
	var err error
	if q.Has("limit") {
		limit, err = strconv.Atoi(q.Get("limit"))
	}
	if err != nil {
		writeErr(w, 400, "BAD_REQUEST", "invalid limit")
		return
	}
	out, err := svc.DiskReport(id, q.Get("cursor"), limit)
	if err != nil {
		writeSettingErr(w, "disk report", err)
		return
	}
	writeJSON(w, 200, out)
}
