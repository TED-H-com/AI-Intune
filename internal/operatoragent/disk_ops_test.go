package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
	"testing"
)

type fakeDiskPolicyHub struct {
	fakeHub
	calls int
}

func (f *fakeDiskPolicyHub) DiskPolicyRead(_ context.Context, id string) (any, error) {
	f.calls++
	body, _ := json.Marshal(store.DefaultDiskPolicy())
	if id != "" {
		return store.OpsPolicy{ID: id, Kind: "disk", Revision: 1, Body: body}, nil
	}
	return []store.OpsPolicy{}, nil
}
func (f *fakeDiskPolicyHub) DiskPolicyUpsert(context.Context, store.DiskPolicyRequest, bool, string) (store.DiskPolicyResult, error) {
	f.calls++
	body, _ := json.Marshal(store.DefaultDiskPolicy())
	return store.DiskPolicyResult{Policy: store.OpsPolicy{ID: "disk-default", Kind: "disk", Revision: 1, Body: body}}, nil
}
func TestDiskPolicyToolsBindingsAndClosedSchema(t *testing.T) {
	f := &fakeDiskPolicyHub{}
	s := &Service{Hub: f}
	if _, err := s.Call(context.Background(), "disk_policy_upsert_apply", json.RawMessage(`{"idempotency_key":"disk-key"}`)); err == nil || callErr(t, err).Code != "preview_digest_required" || f.calls != 0 {
		t.Fatal("missing preview called Hub", err)
	}
	if _, err := s.Call(context.Background(), "disk_policy_get", json.RawMessage(`{"id":"disk-default","unknown":true}`)); err == nil || f.calls != 0 {
		t.Fatal("unknown field accepted")
	}
	for _, name := range []string{"disk_policy_list", "disk_policy_get", "disk_policy_upsert_preview"} {
		raw := json.RawMessage(`{}`)
		if name == "disk_policy_get" {
			raw = json.RawMessage(`{"id":"disk-default"}`)
		}
		if _, err := s.Call(context.Background(), name, raw); err != nil {
			t.Fatal(err)
		}
	}
	for _, tool := range diskPolicyTools() {
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatal("open tool schema", tool.Name)
		}
	}
}

type fakeDiskApprovalHub struct {
	fakeHub
	calls int
	apply bool
}

func (f *fakeDiskApprovalHub) DiskApprovalList(context.Context, string, string, string) ([]store.OpsApproval, error) {
	f.calls++
	return []store.OpsApproval{}, nil
}
func (f *fakeDiskApprovalHub) DiskApprovalDecision(_ context.Context, _ store.OpsApprovalDecisionRequest, apply bool, _ string) (store.OpsApprovalDecisionResult, error) {
	f.calls++
	f.apply = apply
	return store.OpsApprovalDecisionResult{}, nil
}
func TestDiskApprovalToolsBindingsAndClosedSchema(t *testing.T) {
	f := &fakeDiskApprovalHub{}
	s := &Service{Hub: f}
	for _, args := range []string{`{}`, `{"idempotency_key":"decision-key"}`, `{"idempotency_key":"decision-key","preview_digest":"invalid"}`} {
		if _, err := s.Call(context.Background(), "disk_approval_decision_apply", json.RawMessage(args)); err == nil || f.calls != 0 {
			t.Fatal("unbound apply reached Hub", err)
		}
	}
	if _, err := s.Call(context.Background(), "disk_approval_list", json.RawMessage(`{"unknown":true}`)); err == nil || f.calls != 0 {
		t.Fatal("unknown field accepted")
	}
	for _, name := range []string{"disk_approval_list", "disk_approval_decision_preview"} {
		if _, err := s.Call(context.Background(), name, json.RawMessage(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	if f.calls != 2 || f.apply {
		t.Fatal("preview unexpectedly applied")
	}
	for _, tool := range diskApprovalTools() {
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatal("open schema", tool.Name)
		}
	}
}

type privateDiskPolicyHub struct {
	fakeDiskPolicyHub
	policy store.OpsPolicy
}

func (f *privateDiskPolicyHub) DiskPolicyRead(_ context.Context, id string) (any, error) {
	if id == "" {
		return []store.OpsPolicy{f.policy}, nil
	}
	return f.policy, nil
}
func (f *privateDiskPolicyHub) DiskPolicyUpsert(context.Context, store.DiskPolicyRequest, bool, string) (store.DiskPolicyResult, error) {
	return store.DiskPolicyResult{Policy: f.policy, PreviousBody: f.policy.Body, RemovedProtectPaths: []string{"/srv/private-models"}}, nil
}
func TestDiskPolicyMCPRedactsAllPathBearingResponses(t *testing.T) {
	policy := store.DefaultDiskPolicy()
	policy.ProtectPaths = []string{"/srv/private-models", "/srv/private-backups"}
	raw, _ := json.Marshal(policy)
	hub := &privateDiskPolicyHub{policy: store.OpsPolicy{ID: "disk-default", Kind: "disk", Revision: 1, Body: raw}}
	s := &Service{Hub: hub}
	for _, tc := range []struct{ name, args string }{{"disk_policy_list", `{}`}, {"disk_policy_get", `{"id":"disk-default"}`}, {"disk_policy_upsert_preview", `{}`}, {"disk_policy_upsert_apply", `{"idempotency_key":"disk-key","preview_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`}} {
		result, err := s.Call(context.Background(), tc.name, json.RawMessage(tc.args))
		if err != nil {
			t.Fatal(tc.name, err)
		}
		bytes, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range policy.ProtectPaths {
			if strings.Contains(string(bytes), path) {
				t.Fatal("MCP leaked path", tc.name, string(bytes))
			}
		}
		if !strings.Contains(string(bytes), `"count":2`) || !strings.Contains(string(bytes), "sha256:"+scriptcatalog.Digest([]byte(policy.ProtectPaths[0]))) {
			t.Fatal("projection lacks count or path digests", string(bytes))
		}
	}
	hub.policy.Body = json.RawMessage(`{"protect_paths":["/srv/private-models"]}`)
	if _, err := s.Call(context.Background(), "disk_policy_get", json.RawMessage(`{"id":"disk-default"}`)); err == nil || strings.Contains(err.Error(), "/srv/private-models") {
		t.Fatal("malformed response must fail closed", err)
	}
}
