package main

import (
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func configureDiskManifestSigningKey(st *store.Store, path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 32768 {
		return &store.OperatorRequestError{Code: "PRECONDITION_FAILED", Detail: "disk manifest signing key must be a private 0600 regular file"}
	}
	file, err := os.Open(path)
	if err != nil {
		return &store.OperatorRequestError{Code: "PRECONDITION_FAILED", Detail: "disk manifest signing key unavailable"}
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 {
		return &store.OperatorRequestError{Code: "PRECONDITION_FAILED", Detail: "disk manifest signing key changed"}
	}
	raw, err := io.ReadAll(io.LimitReader(file, 32769))
	if err != nil || len(raw) > 32768 {
		return &store.OperatorRequestError{Code: "PRECONDITION_FAILED", Detail: "disk manifest signing key unavailable"}
	}
	return st.ConfigureDiskManifestSigningKey(raw)
}

func (h *hub) handleDiskManifestFetch(w http.ResponseWriter, r *http.Request, machine string) {
	w.Header().Set("Cache-Control", "no-store")
	release, retry := h.diskManifestLimiter.acquire(machine, time.Now())
	if release == nil {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		writeErr(w, 429, "RATE_LIMITED", "disk manifest grant limit reached")
		return
	}
	defer release()

	q := r.URL.Query()
	for key, values := range q {
		if (key != "job_id" && key != "digest") || len(values) != 1 {
			writeErr(w, 400, "BAD_REQUEST", "exact job and digest query required")
			return
		}
	}
	if len(q) != 2 || q.Get("job_id") == "" || q.Get("digest") == "" {
		writeErr(w, 400, "BAD_REQUEST", "exact job and digest required")
		return
	}
	grant, err := h.store.SignedDiskManifestForJob(machine, q.Get("job_id"), r.PathValue("id"), q.Get("digest"))
	if err != nil {
		writeSettingErr(w, "disk manifest", err)
		return
	}
	writeJSON(w, 200, grant)
}

func (h *hub) handleDiskActionResults(w http.ResponseWriter, r *http.Request, machine string) {
	w.Header().Set("Cache-Control", "no-store")
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || r.URL.RawQuery != "" {
		writeErr(w, 400, "BAD_REQUEST", "JSON results required")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
	var req store.DiskActionResults
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || decoder.Decode(new(any)) != io.EOF {
		writeErr(w, 400, "BAD_REQUEST", "invalid action results")
		return
	}
	digest, err := h.store.DiskActionResults(machine, r.PathValue("job_id"), req)
	if err != nil {
		writeSettingErr(w, "action results", err)
		return
	}
	writeJSON(w, 200, struct {
		Digest string `json:"digest"`
	}{digest})
}
