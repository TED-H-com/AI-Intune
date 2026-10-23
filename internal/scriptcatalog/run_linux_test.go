//go:build linux

package scriptcatalog

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testEntry(body string) Entry {
	return Entry{ID: "test-only", Version: "1", Bytes: []byte(body), SHA256: Digest([]byte(body)), RunsAs: "agent-user", Mode: "read", AllowedOS: []string{"linux"}, MaxTimeout: 5, OutputCap: 64, ArgsSchema: Schema{Type: "object", Properties: map[string]Property{}}}
}

func useUnwritableTempDir(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// procfs rejects directory creation even when the helper test runs as root.
	t.Setenv("TMPDIR", "/proc/self")
	if dir, err := os.MkdirTemp(os.TempDir(), "clawctl-script-test-*"); err == nil {
		os.RemoveAll(dir)
		t.Fatal("test requires an unwritable temporary directory")
	}
	return home
}

func TestCreatePrivateScriptDirUsesCacheWithUnwritableTempDir(t *testing.T) {
	home := useUnwritableTempDir(t)
	dir, err := createPrivateScriptDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	parent := filepath.Join(home, ".cache", "clawctl", "scripts")
	if filepath.Dir(dir) != parent {
		t.Fatalf("run directory %q is not under %q", dir, parent)
	}
	for _, path := range []string{parent, dir} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			t.Fatalf("directory %q mode = %v, want 0700", path, info.Mode())
		}
	}
}

func TestCreatePrivateScriptDirFallsBackToTempDir(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "home-file")
	if err := os.WriteFile(home, nil, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", base)
	dir, err := createPrivateScriptDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	if filepath.Dir(dir) != base {
		t.Fatalf("fallback directory %q is not under %q", dir, base)
	}
}

func TestProbeRunsWithUnwritableTempDir(t *testing.T) {
	requireAgentUser(t)
	home := useUnwritableTempDir(t)
	e, _ := Lookup("fleet-probe-v1")
	r, err := Run(context.Background(), e, []byte(`{}`), e.DefaultTimeout)
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("probe failed %+v %v", r, err)
	}
	entries, err := os.ReadDir(filepath.Join(home, ".cache", "clawctl", "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatal("private run directory retained after probe")
	}
}
func TestRunTimeoutKillsProcessGroup(t *testing.T) {
	requireAgentUser(t)
	e := testEntry("sleep 30 &\nwait\n")
	start := time.Now()
	r, err := Run(context.Background(), e, []byte(`{}`), 1)
	if err != nil || !r.TimedOut || r.ExitCode == 0 || time.Since(start) > 3*time.Second {
		t.Fatalf("timeout result %+v %v", r, err)
	}
}
func TestRunCapsHashesAndRedacts(t *testing.T) {
	requireAgentUser(t)
	body := "printf 'token=sample-secret\\n'\ni=0; while [ \"$i\" -lt 100 ]; do printf 'abcdef\\n'; printf 'stderr\\n' >&2; i=$((i+1)); done\n"
	e := testEntry(body)
	r, err := Run(context.Background(), e, []byte(`{}`), 3)
	if err != nil {
		t.Fatal(err)
	}
	if !r.StdoutTruncated || !r.StderrTruncated || len(r.Stdout) > e.OutputCap || len(r.Stderr) > e.OutputCap || strings.Contains(r.Stdout, "sample-secret") || !strings.Contains(r.Stdout, "[REDACTED]") {
		t.Fatalf("cap/redaction failed %+v", r)
	}
	expected := "token=sample-secret\n" + strings.Repeat("abcdef\n", 100)
	if r.StdoutSHA256 != Digest([]byte(expected)) || r.StderrSHA256 != Digest([]byte(strings.Repeat("stderr\n", 100))) {
		t.Fatal("must hash full streams")
	}
}
func TestRunArgsAreLiteralAndEnvironmentClean(t *testing.T) {
	requireAgentUser(t)
	t.Setenv("SCRIPT_TEST_SECRET", "never inherit")
	e := testEntry("cat\nprintf '\\n%s' \"${SCRIPT_TEST_SECRET-unset}\"\n")
	e.OutputCap = 1024
	e.ArgsSchema.Properties["label"] = Property{Type: "string", MaxLength: 128}
	raw := []byte(`{"label":";$()$(printf interpreted)"}`)
	r, err := Run(context.Background(), e, raw, 3)
	if err != nil || r.ExitCode != 0 || r.Stdout != string(raw)+"\nunset" {
		t.Fatalf("literal args or clean env failed %+v %v", r, err)
	}
}
func TestProbeJSONContainsOnlyFacts(t *testing.T) {
	requireAgentUser(t)
	e, _ := Lookup("fleet-probe-v1")
	r, err := Run(context.Background(), e, []byte(`{}`), e.DefaultTimeout)
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("probe failed %+v %v", r, err)
	}
	var facts map[string]any
	if json.Unmarshal([]byte(r.Stdout), &facts) != nil || len(facts) != 4 {
		t.Fatal("probe facts are not JSON")
	}
	for _, key := range []string{"uptime_seconds", "load", "root_disk_use_percent", "failed_systemd_unit_count"} {
		if _, ok := facts[key]; !ok {
			t.Fatalf("missing %s", key)
		}
	}
}
func TestRedaction(t *testing.T) {
	for _, s := range []string{"Bearer sample-value", "api_key=sample-value", "ghp_samplevalue", "sk-samplevalue", strings.Repeat("a", 40)} {
		if Redact(s) == s {
			t.Fatal("secret shape unredacted")
		}
	}
}

func requireAgentUser(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("phase-one script execution tests require a non-root agent user")
	}
}

func TestRunBATUsesPythonAndAgentHome(t *testing.T) {
	requireAgentUser(t)
	e := testEntry("import json, os, sys\nprint(json.dumps({'home': os.environ['HOME'], 'tmp': os.environ['TMPDIR'], 'args': json.load(sys.stdin)}))\n")
	e.ID = "bat-sweep-report-v1"
	e.OutputCap = 4096
	r, err := Run(context.Background(), e, []byte(`{}`), 3)
	if err != nil || r.ExitCode != 0 {
		t.Fatalf("Python execution %+v %v", r, err)
	}
	var out struct {
		Home string         `json:"home"`
		Tmp  string         `json:"tmp"`
		Args map[string]any `json:"args"`
	}
	if err := json.Unmarshal([]byte(r.Stdout), &out); err != nil {
		t.Fatal(err)
	}
	account, err := user.Current()
	if err != nil || out.Home != account.HomeDir || out.Home == out.Tmp || out.Args == nil {
		t.Fatalf("agent config home %+v %v", out, err)
	}
	if _, err := os.Stat(out.Tmp); !os.IsNotExist(err) {
		t.Fatal("private temp directory retained")
	}
}

func TestRunReadReportsUsesIsolatedPythonAndAgentHome(t *testing.T) {
	requireAgentUser(t)
	for _, id := range []string{"oci-cost-report-v1", "network-watch-v1", "bat-release-check-v1"} {
		t.Run(id, func(t *testing.T) {
			// Exercise the real runner without invoking host CLIs or reading credentials.
			e := testEntry("import json, os, sys\nprint(json.dumps({'schema_version':1,'status':'ok','summary':'ok','metrics':{'agent_home':os.environ['HOME'],'isolated':sys.flags.isolated,'no_site':sys.flags.no_site,'args':json.load(sys.stdin)},'findings':[]}))\n")
			e.ID, e.OutputCap = id, 4096
			r, err := Run(context.Background(), e, []byte(`{}`), 3)
			if err != nil || r.ExitCode != 0 || r.Stderr != "" {
				t.Fatalf("report runner: %+v %v", r, err)
			}
			var result struct {
				Metrics struct {
					Home     string `json:"agent_home"`
					Isolated int    `json:"isolated"`
					NoSite   int    `json:"no_site"`
				} `json:"metrics"`
			}
			account, _ := user.Current()
			if json.Unmarshal([]byte(r.Stdout), &result) != nil || result.Metrics.Home != account.HomeDir || result.Metrics.Isolated != 1 || result.Metrics.NoSite != 1 {
				t.Fatalf("invalid runner environment: %s", r.Stdout)
			}
		})
	}
}
