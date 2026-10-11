package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

type fakeDiskPolicyHub struct {
	fakeHub
	calls int
}

func (f *fakeDiskPolicyHub) DiskPolicyRead(context.Context, string) (any, error) {
	f.calls++
	return []store.OpsPolicy{}, nil
}
func (f *fakeDiskPolicyHub) DiskPolicyUpsert(context.Context, store.DiskPolicyRequest, bool, string) (store.DiskPolicyResult, error) {
	f.calls++
	return store.DiskPolicyResult{}, nil
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
