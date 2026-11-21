package operatoragent

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestToolsForFiltersByAllowlist(t *testing.T) {
	if len(ToolsFor(nil)) != len(Tools()) {
		t.Fatal("nil allowlist must list every tool")
	}
	got := ToolsFor([]string{"GET /v1/operator/machines", "GET /v1/operator/deployments/{id}"})
	names := map[string]bool{}
	for _, tool := range got {
		names[tool.Name] = true
	}
	if !names["machines_list"] || !names["fleet_overview"] || !names["rollout_status"] || names["schedule_job_cancel"] || names["rollout_expand"] || len(got) != 4 {
		t.Fatalf("filtered tools %v", names)
	}
	resp, ok := handleMCP(context.Background(), &Service{Allowlist: []string{"GET /v1/operator/hub-status"}}, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	raw, _ := json.Marshal(resp.Result)
	if !ok || !strings.Contains(string(raw), `"hub_status"`) || strings.Contains(string(raw), `"jobs_list"`) {
		t.Fatalf("tools/list %s", raw)
	}
}
