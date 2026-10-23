package operator

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
	"testing"
)

func TestReadReportProjectionRejectsUntrustedText(t *testing.T) {
	secret := "ocid1.tenancy.secret user@example.invalid token=secret private-peer"
	for _, id := range []string{"oci-cost-report-v1", "network-watch-v1", "bat-release-check-v1"} {
		raw, _ := json.Marshal(map[string]any{"schema_version": 1, "status": "warn", "summary": secret, "metrics": map[string]any{"mtd_usd": 12.34, "running_instances": 2, "online_peer_count": 3, "expected_offline_count": 1, "cloudflared_active": false, "installed_version": secret, "latest_stable": "v3.2.15", "newer_available": true, "peer_identity": secret}, "findings": []any{map[string]any{"reason": "expected_peers_offline", "peer": secret}, map[string]any{"reason": secret}}})
		out := projectReadReport(store.ReadReportReceipt{ScriptID: id, JobID: "job", Output: string(raw)})
		encoded, _ := json.Marshal(out)
		for _, bad := range []string{"ocid1", "user@", "token=secret", "private-peer"} {
			if strings.Contains(string(encoded), bad) {
				t.Fatalf("identity leaked: %s", encoded)
			}
		}
		if out.Status != "warn" || len(out.Metrics) == 0 || len(out.Findings) != 2 {
			t.Fatal(out)
		}
	}
}
func TestReadReportIncompleteAndStatusSemantics(t *testing.T) {
	if out := projectReadReport(store.ReadReportReceipt{ScriptID: "oci-cost-report-v1", JobID: "job", ProcessFailed: true, Output: `{"schema_version":1,"status":"ok"}`}); out.Status != "error" {
		t.Fatal(out)
	}
	for _, raw := range []string{``, `{"schema_version":2,"status":"ok"}`, `{"schema_version":1,"status":"green"}`, strings.Repeat("x", 65537)} {
		out := projectReadReport(store.ReadReportReceipt{ScriptID: "oci-cost-report-v1", JobID: "job", Output: raw})
		if out.Status != "error" {
			t.Fatal(out)
		}
	}
	for _, status := range []string{"ok", "warn", "urgent", "error"} {
		out := projectReadReport(store.ReadReportReceipt{ScriptID: "oci-cost-report-v1", JobID: "job", Output: `{"schema_version":1,"status":"` + status + `","metrics":{"mtd_usd":-1,"running_instances":1.2}}`})
		if out.Status != status || out.Metrics[0].Value != "Unknown / 未知" || out.Metrics[1].Value != "Unknown / 未知" {
			t.Fatal(out)
		}
	}
	if out := projectReadReport(store.ReadReportReceipt{}); out.Status != "unknown" {
		t.Fatal(out)
	}
}
