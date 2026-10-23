package operatorclient

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadinessClient(t *testing.T) {
	result := store.HostChecklist{MachineID: "example", Items: make([]store.ReadinessItem, 10)}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operator/machines/example/readiness" || r.Method != "GET" {
			t.Error("wrong request")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	c := operatorClientForServer(t, server)
	if _, err := c.MachineReadiness(t.Context(), "example"); err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{7, 26} {
		result.Items = make([]store.ReadinessItem, count)
		result.NeedsYou = 1
		if got, err := c.MachineReadiness(t.Context(), "example"); err != nil || got.NeedsYou != 1 {
			t.Fatal(got, err)
		}
	}
	result.Items = nil
	if _, err := c.MachineReadiness(t.Context(), "example"); err == nil {
		t.Fatal("accepted empty checklist")
	}
	result.Items = make([]store.ReadinessItem, 10)
	result.MachineID = "other"
	if _, err := c.MachineReadiness(t.Context(), "example"); err == nil {
		t.Fatal("accepted mismatched identity")
	}
	for _, id := range []string{"", "..", "a/b"} {
		if _, err := c.MachineReadiness(t.Context(), id); err == nil {
			t.Fatal("accepted malformed id")
		}
	}
}
