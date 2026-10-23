package operatorclient

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostProfileStrictClient(t *testing.T) {
	result := store.FleetHostProfile{Hosts: []store.HostProfileStatus{}}
	result.Digest, _ = result.Profile.Digest()
	bad := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/operator/host-profile" || r.Method != "GET" {
			t.Error("wrong route")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if bad != "" {
			_, _ = w.Write([]byte(bad))
			return
		}
		_ = json.NewEncoder(w).Encode(result)
	}))
	defer server.Close()
	c := operatorClientForServer(t, server)
	if _, err := c.HostProfile(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{`{"profile":{},"digest":"bad","hosts":[]}`, `{"profile":{},"unknown":true}`, `{} {}`} {
		bad = raw
		if _, err := c.HostProfile(t.Context()); err == nil {
			t.Fatal("accepted invalid response")
		}
	}
}
