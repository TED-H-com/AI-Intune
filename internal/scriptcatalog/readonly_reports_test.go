package scriptcatalog

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadReportContracts(t *testing.T) {
	for _, id := range []string{"oci-cost-report-v1", "network-watch-v1", "bat-release-check-v1"} {
		e, ok := Lookup(id)
		if !ok || !IsReadReport(id) || e.Mode != "read" || e.RunsAs != "agent-user" || e.OutputCap != 64<<10 || e.MaxTimeout > 600 || e.DefaultTimeout > e.MaxTimeout || !e.AllowsOS("linux") || e.AllowsOS("darwin") || e.AllowsOS("windows") || Digest(e.Bytes) != e.SHA256 {
			t.Fatalf("invalid report constraints: %s", id)
		}
		if e.ArgsSchema.AdditionalProperties {
			t.Fatal("report schema must be closed")
		}
	}
	for _, tc := range []struct {
		id, args string
		valid    bool
	}{
		{"oci-cost-report-v1", `{"profile":"sample-oci-a"}`, true},
		{"oci-cost-report-v1", `{"profile":"sample-oci-b","warn_usd":0.01,"urgent_usd":5.25}`, true},
		{"oci-cost-report-v1", `{}`, false},
		{"oci-cost-report-v1", `{"profile":"../sample-oci-a"}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","oci_path":"/tmp/oci"}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","warn_usd":-0.01}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","warn_usd":6}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","urgent_usd":true}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","urgent_usd":"5"}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","urgent_usd":1e400}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","urgent_usd":1000001}`, false},
		{"oci-cost-report-v1", `{"profile":"sample-oci-a","warn_usd":0,"warn_usd":1}`, false},
		{"network-watch-v1", `{}`, true},
		{"network-watch-v1", `{"expected_peers":["peer-a"],"resolve":["github.com"],"mode":"daily"}`, true},
		{"network-watch-v1", `{"expected_peers":[],"resolve":[]}`, true},
		{"network-watch-v1", `{"expected_peers":["--shell"]}`, false},
		{"network-watch-v1", `{"expected_peers":["user@example.invalid"]}`, false},
		{"network-watch-v1", `{"expected_peers":[1]}`, false},
		{"network-watch-v1", `{"resolve":["a","b","c","d","e","f","g","h","i"]}`, false},
		{"network-watch-v1", `{"baseline_listen_digest":"` + strings.Repeat("a", 64) + `","baseline_listen_ports":["1","65535"]}`, true},
		{"network-watch-v1", `{"baseline_listen_ports":["443"]}`, false},
		{"network-watch-v1", `{"baseline_listen_digest":"bad"}`, false},
		{"network-watch-v1", `{"mode":"arbitrary"}`, false},
		{"bat-release-check-v1", `{}`, true},
		{"bat-release-check-v1", `{"download":false}`, false},
		{"bat-release-check-v1", `{"repo":"other/repo"}`, false},
	} {
		e, _ := Lookup(tc.id)
		_, err := e.Validate(json.RawMessage(tc.args))
		if (err == nil) != tc.valid {
			t.Errorf("%s %s: %v", tc.id, tc.args, err)
		}
	}
	e, _ := Lookup("network-watch-v1")
	for _, port := range []string{"0", "65536", "99999", "01", "-1"} {
		args := `{"baseline_listen_digest":"` + strings.Repeat("a", 64) + `","baseline_listen_ports":["` + port + `"]}`
		if _, err := e.Validate(json.RawMessage(args)); err == nil {
			t.Errorf("accepted invalid port %q", port)
		}
	}
	tooMany, _ := json.Marshal(map[string]any{"expected_peers": make([]string, 33)})
	if _, err := e.Validate(tooMany); err == nil {
		t.Fatal("accepted too many peers")
	}
}

func TestReadReportRedactionPreservesOnlyNetworkMetricDigest(t *testing.T) {
	digest := strings.Repeat("a", 64)
	raw := []byte(`{"schema_version":1,"status":"warn","metrics":{"listen_digest":"` + digest + `","other":"` + digest + `"},"findings":[{"reason":"token=example"}],"summary":"identity user@example.invalid ocid1.tenancy.example"}`)
	for _, id := range []string{"network-watch-v1", "oci-cost-report-v1", "bat-release-check-v1"} {
		clean := RedactReadReportJSON(id, raw)
		var result struct {
			Metrics map[string]string `json:"metrics"`
		}
		if json.Unmarshal([]byte(clean), &result) != nil || strings.Contains(clean, "user@") || strings.Contains(clean, "ocid1.") || strings.Contains(clean, "token=example") || result.Metrics["other"] == digest {
			t.Fatalf("unsafe redaction: %s", clean)
		}
		if (result.Metrics["listen_digest"] == digest) != (id == "network-watch-v1") {
			t.Fatalf("digest exemption escaped report field: %s", clean)
		}
		if RedactReadReportJSON(id, []byte(clean)) != clean {
			t.Fatal("Hub redaction must preserve agent redaction")
		}
	}
	for _, raw := range []string{"{", "{} {}", "null", strings.Repeat("x", 65537)} {
		if RedactReadReportJSON("network-watch-v1", []byte(raw)) != "" {
			t.Fatal("accepted malformed or oversized output")
		}
	}
	raw = []byte(`{"user@example.invalid":"sensitive-key","metrics":{"nested":{"listen_digest":"` + digest + `"}},"listen_digest":"` + digest + `"}`)
	clean := RedactReadReportJSON("network-watch-v1", raw)
	if strings.Contains(clean, "user@") || strings.Contains(clean, digest) {
		t.Fatalf("redaction exemption escaped exact metric path: %s", clean)
	}
}

func TestReadReportPATHShims(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Fatal("Python 3 is required for embedded report tests")
	}
	cmd := exec.Command(python, "-B", "-m", "unittest", "readonly_reports_test")
	cmd.Env = append(os.Environ(), "TMPDIR="+t.TempDir(), "PYTHONDONTWRITEBYTECODE=1")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("read-only report shim tests: %v\n%s", err, out)
	}
}

func TestRetirementScheduleExamplesStayDisabled(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "runbooks", "retirement-phase0-schedules.example.json"))
	if err != nil {
		t.Fatal(err)
	}
	var examples []struct {
		ScriptID string          `json:"script_id"`
		SHA256   string          `json:"script_sha256"`
		Args     json.RawMessage `json:"args"`
		Enabled  *bool           `json:"enabled"`
		CatchUp  *bool           `json:"catch_up"`
		Cron     string          `json:"cron"`
	}
	if err := json.Unmarshal(raw, &examples); err != nil || len(examples) != 5 {
		t.Fatalf("schedule examples: %v", err)
	}
	for i, example := range examples {
		e, ok := Lookup(example.ScriptID)
		if !ok || example.SHA256 != e.SHA256 || example.Enabled == nil || *example.Enabled || example.CatchUp == nil || *example.CatchUp || example.Cron != []string{"15 9 * * *", "20 9 * * *", "17 */6 * * *", "45 3 * * *", "0 10 * * *"}[i] {
			t.Fatalf("unsafe or stale example: %d", i)
		}
		if _, err := e.Validate(example.Args); err != nil {
			t.Fatal(err)
		}
	}
}
