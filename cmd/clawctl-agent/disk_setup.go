package main

import (
	"bytes"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"io"
	"os"
	"path/filepath"
)

func adoptDiskJobsAt(dir string, jobs []model.DiskJob) error {
	if len(jobs) > 128 {
		return os.ErrInvalid
	}
	if jobs == nil {
		jobs = []model.DiskJob{}
	}
	seen := map[string]bool{}
	for _, j := range jobs {
		if e := j.Validate(); e != nil {
			return e
		}
		if seen[j.ID] {
			return os.ErrInvalid
		}
		seen[j.ID] = true
	}
	raw, e := json.Marshal(jobs)
	if e != nil {
		return e
	}
	if len(raw) > 65536 {
		return os.ErrInvalid
	}
	path := filepath.Join(dir, "disk-jobs.json")
	if old, e := os.ReadFile(path); e == nil && bytes.Equal(old, raw) {
		if info, e := os.Lstat(path); e == nil && info.Mode().IsRegular() && info.Mode().Perm() == 0600 {
			return nil
		}
	}
	return writeModeFile(path, raw, 0600)
}

// Read only results for the last delivered jobs. Historical receipts stay on
// disk for replay protection and cannot crowd out a newer result.
func readPendingDiskJobResults(dir string) []model.DiskJobResult {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	f, err := os.Open(filepath.Join(home, ".config", "clawctl", "disk-jobs.json"))
	if err != nil {
		return nil
	}
	raw, err := io.ReadAll(io.LimitReader(f, 65537))
	f.Close()
	if err != nil || len(raw) > 65536 {
		return nil
	}
	var jobs []model.DiskJob
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&jobs) != nil || len(jobs) > 128 {
		return nil
	}
	return readDiskJobResults(dir, jobs)
}
func readDiskJobResults(dir string, jobs []model.DiskJob) []model.DiskJobResult {
	out := []model.DiskJobResult{}
	if len(jobs) > 128 {
		return out
	}
	for _, job := range jobs {
		id := job.ID
		if !model.DiskJobID.MatchString(id) {
			continue
		}
		path := filepath.Join(dir, id+".json")
		entry, e := os.Lstat(path)
		if e != nil || !entry.Mode().IsRegular() {
			continue
		}
		f, e := os.Open(path)
		if e != nil {
			continue
		}
		raw, e := io.ReadAll(io.LimitReader(f, 8193))
		f.Close()
		if e != nil || len(raw) > 8192 {
			continue
		}
		var r model.DiskJobResult
		d := json.NewDecoder(bytes.NewReader(raw))
		d.DisallowUnknownFields()
		if d.Decode(&r) != nil {
			continue
		}
		var tail any
		if d.Decode(&tail) != io.EOF {
			continue
		}
		r.ID = id
		if r.Valid() {
			out = append(out, r)
		}
	}
	return out
}
