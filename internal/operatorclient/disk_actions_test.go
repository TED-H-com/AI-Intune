package operatorclient

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestDiskActionClientCreatedReplayAndBinding(t *testing.T) {
	base, _ := url.Parse("http://100.64.0.1:8787")
	req := store.OpsApprovalDecisionRequest{ID: "approval-fixture", Decision: "approved", Reason: "reviewed", ItemDigest: "sha256:" + strings.Repeat("a", 64), PreviewDigest: "sha256:" + strings.Repeat("b", 64)}
	for _, tc := range []struct {
		name        string
		status      int
		replay, bad bool
	}{{"created", 201, false, false}, {"replayed", 200, true, false}, {"wrong-digest", 201, false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			c := &Client{base: base, http: &http.Client{Transport: assignedUserTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Path != "/v1/operator/disk-ops/actions/decide" || r.Header.Get("Idempotency-Key") != "fixture-key" {
					t.Fatal("wrong dispatch request", r.URL, r.Header)
				}
				out := store.OpsApprovalDecisionResult{Approval: store.OpsApproval{ID: req.ID, ItemDigest: req.ItemDigest, JobID: "job-fixture", State: "consumed"}, Request: req, PreviewDigest: req.PreviewDigest, Replayed: tc.replay}
				if tc.bad {
					out.Approval.ItemDigest = "sha256:" + strings.Repeat("c", 64)
				}
				raw, _ := json.Marshal(out)
				headers := http.Header{"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}}
				if tc.replay {
					headers.Set("Idempotency-Replayed", "true")
				}
				return &http.Response{StatusCode: tc.status, Header: headers, Body: io.NopCloser(strings.NewReader(string(raw))), Request: r}, nil
			})}}
			out, err := c.DiskActionDecide(context.Background(), req, "fixture-key", false)
			if (err != nil) != tc.bad || (!tc.bad && out.Replayed != tc.replay) {
				t.Fatal(out, err)
			}
		})
	}
}
