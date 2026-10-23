package scriptcatalog

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestActionCatalogClosedArgsAndDedicatedRunner(t *testing.T) {
	for _, id := range []string{DiskActionScript("quarantine"), DiskActionScript("delete"), DiskActionScript("restore"), DiskActionScript("expire")} {
		e, ok := Lookup(id)
		if !ok || e.Mode != "write" || Digest(e.Bytes) != e.SHA256 || !IsDisk(id) || !IsDiskAction(id) {
			t.Fatal("unsafe action registry", id)
		}
		args := json.RawMessage(`{"manifest_id":"manifest-1","manifest_digest":"sha256:` + strings.Repeat("a", 64) + `","approval_id":"approval-1"}`)
		if id == DiskActionScript("expire") {
			args = json.RawMessage(`{"policy_id":"policy-1","policy_digest":"sha256:` + strings.Repeat("a", 64) + `"}`)
		}
		if _, err := e.Validate(args); err != nil {
			t.Fatal(err)
		}
		if _, err := e.Validate(json.RawMessage(`{"path":"/tmp/anything","command":"rm"}`)); err == nil {
			t.Fatal("caller paths accepted")
		}
		if _, err := RunPolicy(context.Background(), e, args, e.DefaultTimeout, nil); err == nil {
			t.Fatal("unsigned runner admitted action")
		}
		if _, err := RunDiskAction(context.Background(), e, args, e.DefaultTimeout, DiskActionRun{}); err == nil {
			t.Fatal("empty authority admitted")
		}
	}
	raw := []byte(`{"schema":"disk-action-result/v1","job_id":"job-example","items":[{"manifest_id":"manifest-` + strings.Repeat("a", 32) + `","item_id":"item-1","status":"quarantined"}],"quarantined_bytes":4096,"freed_bytes":0}`)
	clean := RedactDiskJSON(raw)
	if !strings.Contains(clean, "manifest-"+strings.Repeat("a", 32)) || !strings.Contains(clean, "disk-action-result/v1") {
		t.Fatal("safe action receipt IDs lost")
	}
}
