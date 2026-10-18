package operatorclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operator"
)

func TestMachineSafeClientReadAndValidation(t *testing.T) {
	result := operator.MachineSafeResult{
		SchemaVersion: 1, Projection: map[string]any{"detail": map[string]any{}},
		Redactions: 1, Redacted: true, RedactionFlags: []string{"credential_assignment"}, ScrubberVersion: 1,
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/operator/machines/example/safe" || r.URL.RawQuery != "" {
			t.Error("incorrect request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	c := operatorClientForServer(t, server)
	if out, err := c.MachineSafe(t.Context(), "example"); err != nil || out.Redactions != 1 {
		t.Fatalf("read: %v", err)
	}
	result.RedactionFlags = []string{"unknown"}
	if _, err := c.MachineSafe(t.Context(), "example"); err == nil {
		t.Fatal("accepted unknown redaction flag")
	}
	result.RedactionFlags = []string{}
	if _, err := c.MachineSafe(t.Context(), "example"); err == nil {
		t.Fatal("accepted inconsistent redaction metadata")
	}
	for _, id := range []string{"", "..", "a/b"} {
		if _, err := c.MachineSafe(t.Context(), id); err == nil {
			t.Fatal("accepted malformed ID")
		}
	}
}
