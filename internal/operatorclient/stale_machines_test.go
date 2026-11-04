package operatorclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestStaleMachineCandidatesStrictContract(t *testing.T) {
	now := time.Now().UTC()
	valid := operator.StaleMachineReview{SchemaVersion: 1, EvaluatedAt: now, Limit: 100, Items: []operator.StaleMachineReviewItem{{MachineID: "unused", DisplayName: "host", Hostname: "", CreatedAt: now.Add(-25 * time.Hour), Branches: []store.StaleMachineBranch{store.StaleMachineAbandoned24h}, DuplicateOf: []string{}}}}
	raw, _ := json.Marshal(valid)
	for _, tc := range []struct {
		name   string
		body   string
		header string
		status int
		ok     bool
	}{
		{name: "valid", body: string(raw), ok: true},
		{name: "empty", body: strings.Replace(string(raw), string(mustStaleItemJSON(t, valid.Items)), "[]", 1), ok: true},
		{name: "unknown", body: strings.Replace(string(raw), `"schema_version":1`, `"extra":1,"schema_version":1`, 1)},
		{name: "duplicate", body: strings.Replace(string(raw), `"limit":100`, `"limit":100,"limit":100`, 1)},
		{name: "missing", body: strings.Replace(string(raw), `"truncated":false,`, "", 1)},
		{name: "null items", body: strings.Replace(string(raw), string(mustStaleItemJSON(t, valid.Items)), "null", 1)},
		{name: "inconsistent branch", body: strings.Replace(string(raw), "abandoned-24h", "unknown", 1)},
		{name: "young", body: strings.Replace(string(raw), valid.Items[0].CreatedAt.Format(time.RFC3339Nano), now.Format(time.RFC3339Nano), 1)},
		{name: "false bound", body: strings.Replace(string(raw), `"truncated":false`, `"truncated":true`, 1)},
		{name: "replay", body: string(raw), header: "Idempotency-Replayed"},
		{name: "etag", body: string(raw), header: "ETag"},
		{name: "cache", body: string(raw), header: "Cache-Control"},
		{name: "unauthorized", body: `{"error":"denied"}`, status: 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.RequestURI() != "/v1/operator/stale-machines" {
					t.Error("wrong request")
				}
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				if tc.header != "" {
					w.Header().Set(tc.header, "true")
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				w.Write([]byte(tc.body))
			}))
			defer server.Close()
			out, err := operatorClientForServer(t, server).StaleMachineCandidates(context.Background())
			if (err == nil) != tc.ok {
				t.Fatalf("ok=%v result=%+v err=%v", tc.ok, out, err)
			}
		})
	}
}
func mustStaleItemJSON(t *testing.T, items []operator.StaleMachineReviewItem) []byte {
	t.Helper()
	raw, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
