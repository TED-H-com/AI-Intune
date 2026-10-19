package main

import (
	"bytes"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// The observer only writes data in its existing writable config directory.
func adoptHostProfileAt(dir string, resp model.CheckinResponse) error {
	if resp.HostProfile == nil {
		return nil
	}
	digest, err := resp.HostProfile.Digest()
	if err != nil {
		return err
	}
	if digest != resp.HostProfileDigest {
		return os.ErrInvalid
	}
	path := filepath.Join(dir, "host-profile.json")
	if raw, e := os.ReadFile(path); e == nil {
		if old, e := model.ParseHostProfile(raw); e == nil {
			if d, _ := old.Digest(); d == digest {
				return nil
			}
		}
	}
	raw, err := resp.HostProfile.Canonical()
	if err != nil {
		return err
	}
	return writeModeFile(path, raw, 0600)
}
func adoptHostProfile(resp model.CheckinResponse) error {
	if runtime.GOOS != "linux" {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".config", "clawctl")
	if err := adoptDiskJobsAt(dir, resp.DiskJobs); err != nil {
		return err
	}
	return adoptHostProfileAt(dir, resp)
}
func readHostApplyResult(path string) *model.HostApplyResult {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, (64<<10)+1))
	if err != nil || len(raw) > 64<<10 {
		return nil
	}
	var out model.HostApplyResult
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&out) != nil || out.Schema != "clawctl-fleet-apply/v1" || len(out.Items) > 10 {
		return nil
	}
	var tail any
	if d.Decode(&tail) != io.EOF {
		return nil
	}
	if !model.ValidHostApplyResult(&out) {
		return nil
	}
	return &out
}
