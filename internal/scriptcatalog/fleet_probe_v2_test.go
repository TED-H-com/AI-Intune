package scriptcatalog

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFleetProbeV2Platforms(t *testing.T) {
	e, ok := Lookup("fleet-probe-v2")
	v1, _ := Lookup("fleet-probe-v1")
	if !ok || !e.AllowsOS("Darwin") || !e.AllowsOS("macOS") || !e.AllowsOS("linux") || e.AllowsOS("windows") || v1.AllowsOS("darwin") {
		t.Fatal("incorrect platform allowance")
	}
	if e.Mode != "read" || e.RunsAs != "agent-user" || e.DefaultTimeout != v1.DefaultTimeout || e.MaxTimeout != v1.MaxTimeout || e.OutputCap != v1.OutputCap || Digest(e.Bytes) != e.SHA256 {
		t.Fatal("incorrect probe constraints")
	}
	if _, err := e.Validate([]byte("{}")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Validate([]byte(`{"extra":true}`)); err == nil {
		t.Fatal("accepted args")
	}
}

func TestFleetProbeV2Output(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("requires POSIX shell")
	}
	for _, tc := range []struct{ name, status, want string }{
		{"linux", "", "null"},
		{"darwin", "ok", "2"},
		{"darwin", "fail", "null"},
	} {
		t.Run(tc.name+tc.status, func(t *testing.T) {
			if tc.name == "linux" && runtime.GOOS != "linux" {
				t.Skip("requires Linux procfs")
			}
			dir := t.TempDir()
			fixtures := map[string]string{}
			if tc.name == "darwin" {
				fixtures["uname"] = "echo Darwin"
				fixtures["date"] = "echo 1700000123"
				fixtures["sysctl"] = `case "$2" in
kern.boottime) echo '{ sec = 1700000000, usec = 123456 } Mon Nov 13 00:00:00 2023' ;;
vm.loadavg) echo '{ 1.25 2.50 3.75 }' ;;
*) exit 1 ;;
esac`
				fixtures["df"] = "printf 'Filesystem 512-blocks Used Available Capacity Mounted on\n/dev/disk 100 42 58 42%% /\n'"
				fixtures["launchctl"] = "printf 'PID Status Label\n- 0 private.zero\n123 - private.running\n- -9 private.signal\n- 78 private.failed\n- text private.invalid\n'"
				if tc.status == "fail" {
					fixtures["launchctl"] = "exit 1"
				}
			} else {
				fixtures["systemctl"] = "exit 1"
			}
			for name, body := range fixtures {
				if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			e, _ := Lookup("fleet-probe-v2")
			cmd := exec.Command("/bin/sh")
			cmd.Stdin = strings.NewReader(string(e.Bytes))
			cmd.Env = []string{"PATH=" + dir + ":/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"}
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("probe failed: %v", err)
			}
			var got struct {
				OS     string          `json:"os"`
				Uptime int             `json:"uptime_seconds"`
				Load   []float64       `json:"load"`
				Disk   int             `json:"root_disk_use_percent"`
				Failed json.RawMessage `json:"failed_service_count"`
			}
			var fields map[string]json.RawMessage
			if json.Unmarshal(raw, &got) != nil || json.Unmarshal(raw, &fields) != nil || len(fields) != 5 || strings.Count(string(raw), "\n") != 1 || got.OS != tc.name || got.Uptime < 0 || len(got.Load) != 3 || string(got.Failed) != tc.want {
				t.Fatalf("invalid facts: %s", raw)
			}
			if tc.name == "darwin" && (got.Uptime != 123 || got.Disk != 42 || got.Load[0] != 1.25 || got.Load[1] != 2.5 || got.Load[2] != 3.75) {
				t.Fatalf("incorrect Darwin facts: %s", raw)
			}
		})
	}
}
