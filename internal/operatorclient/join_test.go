package operatorclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestJoinRequestsListSafeContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/operator/joins" {
			t.Error("wrong read route")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Write([]byte(`{"requests":[{"join_code":"ABCD-2345","hostname":"host-b","os":"linux","arch":"amd64","user":"operator","client_ip":"192.0.2.10","created_at":"2026-10-18T00:00:00Z","expires_at":"2026-10-18T00:15:00Z","state":"pending"}]}`))
	}))
	defer server.Close()
	c := operatorClientForServer(t, server)
	rows, err := c.JoinRequestsList(context.Background())
	if err != nil || len(rows) != 1 || rows[0].Code != "ABCD-2345" {
		t.Fatal("join metadata read", err)
	}
}
