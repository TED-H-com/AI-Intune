package operatorclient

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestDiskPolicyClientResponseShapes(t *testing.T) {
	base, _ := url.Parse("http://hub.example.test")
	digest := "sha256:" + strings.Repeat("a", 64)
	calls := 0
	bad := false
	client := &Client{base: base, http: &http.Client{Transport: assignedUserTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == "GET" {
			if strings.HasSuffix(r.URL.Path, "/disk-default") {
				json.NewEncoder(w).Encode(store.OpsPolicy{ID: "disk-default", Kind: "disk", Revision: 1, Digest: digest, Body: json.RawMessage(`{}`)})
			} else {
				json.NewEncoder(w).Encode(struct {
					Items []store.OpsPolicy `json:"items"`
				}{[]store.OpsPolicy{}})
			}
		} else {
			if r.URL.Path == "/v1/operator/disk-ops/policies" {
				if r.Header.Get("Idempotency-Key") != "disk-key" {
					t.Error("apply missing key")
				}
				w.WriteHeader(201)
			}
			receipt := store.DiskPolicyResult{PreviewDigest: digest, Warnings: []string{}, ExpectedRevision: 0, ExpiresAt: time.Now().Add(30 * time.Minute)}
			if bad {
				receipt.PreviewDigest = "sha256:" + strings.Repeat("b", 64)
			}
			json.NewEncoder(w).Encode(receipt)
		}
		res := w.Result()
		res.Request = r
		return res, nil
	})}}
	for _, id := range []string{"", "disk-default"} {
		if _, err := client.DiskPolicyRead(context.Background(), id); err != nil {
			t.Fatal(err)
		}
	}
	rev := int64(0)
	raw, _ := json.Marshal(store.DefaultDiskPolicy())
	body := store.DiskPolicyRequest{ID: "disk-default", Body: raw, ExpectedRevision: &rev, Reason: "review policy"}
	if _, err := client.DiskPolicyUpsert(context.Background(), body, false, ""); err != nil {
		t.Fatal(err)
	}
	prior := calls
	if _, err := client.DiskPolicyUpsert(context.Background(), body, true, "disk-key"); err == nil || calls != prior {
		t.Fatal("unbound apply reached Hub")
	}
	body.PreviewDigest = digest
	if _, err := client.DiskPolicyUpsert(context.Background(), body, true, "disk-key"); err != nil {
		t.Fatal(err)
	}
	bad = true
	if _, err := client.DiskPolicyUpsert(context.Background(), body, true, "disk-key"); err == nil {
		t.Fatal("receipt mismatch accepted")
	}
}

func TestDiskApprovalClientResponseBindings(t *testing.T) {
	base, _ := url.Parse("http://hub.example.test")
	digest := "sha256:" + strings.Repeat("a", 64)
	calls := 0
	bad := false
	replay := false
	client := &Client{base: base, http: &http.Client{Transport: assignedUserTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		w := httptest.NewRecorder()
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			if r.URL.Query().Get("state") != "pending" || r.URL.Query().Get("machine_id") != "example-device" || r.URL.Query().Get("operation") != "quarantine" {
				t.Error("filters lost")
			}
			json.NewEncoder(w).Encode(map[string]any{"items": []store.OpsApproval{}})
		} else {
			if !strings.HasSuffix(r.URL.Path, "/preview") {
				if r.Header.Get("Idempotency-Key") != "decision-key" {
					t.Error("missing retry key")
				}
				if replay {
					w.Header().Set("Idempotency-Replayed", "true")
					w.WriteHeader(200)
				} else {
					w.WriteHeader(201)
				}
			}
			receipt := store.OpsApprovalDecisionResult{Approval: store.OpsApproval{ID: "example-approval"}, PreviewDigest: digest, Replayed: replay}
			if bad {
				receipt.Approval.ID = "different-approval"
			}
			json.NewEncoder(w).Encode(receipt)
		}
		response := w.Result()
		response.Request = r
		return response, nil
	})}}
	ctx := context.Background()
	if _, err := client.DiskApprovalList(ctx, "pending", "example-device", "quarantine"); err != nil {
		t.Fatal(err)
	}
	req := store.OpsApprovalDecisionRequest{ID: "example-approval", Decision: "approved", Reason: "reviewed"}
	if _, err := client.DiskApprovalDecision(ctx, req, false, ""); err != nil {
		t.Fatal(err)
	}
	prior := calls
	if _, err := client.DiskApprovalDecision(ctx, req, true, "decision-key"); err == nil || calls != prior {
		t.Fatal("unbound apply reached Hub")
	}
	req.PreviewDigest = digest
	if _, err := client.DiskApprovalDecision(ctx, req, true, "decision-key"); err != nil {
		t.Fatal(err)
	}
	replay = true
	if _, err := client.DiskApprovalDecision(ctx, req, true, "decision-key"); err != nil {
		t.Fatal(err)
	}
	bad = true
	if _, err := client.DiskApprovalDecision(ctx, req, true, "decision-key"); err == nil {
		t.Fatal("wrong receipt accepted")
	}
}
