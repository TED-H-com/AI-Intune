package operatorclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMachineDisksStrictReadClient(t *testing.T) {
	body := `{"devices":[],"jobs":[]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/operator/machines/example/disks" {
			t.Error("wrong route")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	c := operatorClientForServer(t, server)
	if _, err := c.MachineDisks(t.Context(), "example"); err != nil {
		t.Fatal(err)
	}
	for _, b := range []string{`{}`, `{"devices":[],"jobs":[],"unknown":true}`, `{"devices":[],"jobs":[]} {}`, `{"devices":null,"jobs":[]}`} {
		body = b
		if _, err := c.MachineDisks(t.Context(), "example"); err == nil {
			t.Fatal("accepted", b)
		}
	}
	for _, id := range []string{"", "../other", "a/b"} {
		if _, err := c.MachineDisks(t.Context(), id); err == nil {
			t.Fatal("unsafe ID", id)
		}
	}
}
