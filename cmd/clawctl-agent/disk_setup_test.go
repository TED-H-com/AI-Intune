package main

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestAdoptDiskJobsAndRelayResults(t *testing.T) {
	dir := t.TempDir()
	j := model.DiskJob{ID: "example-job", Device: "/dev/nvme1n1", Serial: "example", SizeBytes: 2 << 30, MountPoint: "/data", FSType: "ext4", Label: "data", Owner: "agent"}
	if err := adoptDiskJobsAt(dir, []model.DiskJob{j}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "disk-jobs.json")
	s, err := os.Stat(p)
	if err != nil || s.Mode().Perm() != 0600 {
		t.Fatal(s, err)
	}
	if err = adoptDiskJobsAt(dir, []model.DiskJob{j, j}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err = adoptDiskJobsAt(dir, nil); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(p)
	if string(raw) != "[]" {
		t.Fatal(string(raw))
	}
	result := model.DiskJobResult{State: "done", UUID: "12345678", MountPoint: "/data", DF: "example"}
	raw, _ = json.Marshal(result)
	if err = os.WriteFile(filepath.Join(dir, "example-job.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	for name, raw := range map[string]string{"bad-result.json": `{"state":"done","force":true}`, "oversize-result.json": string(make([]byte, 8193)), "trailing-result.json": `{"state":"done"} {}`} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(raw), 0600); err != nil {
			t.Fatal(err)
		}
	}
	out := readDiskJobResults(dir, []model.DiskJob{j, {ID: "bad-result"}, {ID: "oversize-result"}, {ID: "trailing-result"}})
	if len(out) != 1 || out[0].ID != "example-job" || out[0].State != "done" {
		t.Fatal(out)
	}
}
