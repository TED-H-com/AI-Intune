package main

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"os"
	"path/filepath"
	"testing"
)

func TestHostProfileHandoff(t *testing.T) {
	dir := t.TempDir()
	yes := true
	p := model.HostProfile{LidIgnore: &yes}
	d, _ := p.Digest()
	r := model.CheckinResponse{HostProfile: &p, HostProfileDigest: d}
	if err := adoptHostProfileAt(dir, r); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "host-profile.json")
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.Mode().Perm() != 0600 {
		t.Fatal(before.Mode())
	}
	if err = adoptHostProfileAt(dir, r); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !before.ModTime().Equal(after.ModTime()) {
		t.Fatal("unchanged profile rewritten")
	}
	r.HostProfileDigest = "wrong"
	if adoptHostProfileAt(dir, r) == nil {
		t.Fatal("bad digest accepted")
	}
	if readHostApplyResult(filepath.Join(dir, "missing")) != nil {
		t.Fatal("invented result")
	}
	if err = os.WriteFile(filepath.Join(dir, "last.json"), []byte(`{"schema":"unknown"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if readHostApplyResult(filepath.Join(dir, "last.json")) != nil {
		t.Fatal("unknown schema accepted")
	}
}
