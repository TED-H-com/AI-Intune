package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/maintenance"
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

func (f *fakeDiskPolicyHub) DiskOpsStatus(_ context.Context, id string) (store.DiskOpsStatus, error) {
	f.calls++
	return store.DiskOpsStatus{MachineID: id, Thresholds: store.DefaultDiskPolicy().Thresholds}, nil
}
func TestDiskOpsStatusToolClosedArguments(t *testing.T) {
	f := &fakeDiskPolicyHub{}
	s := &Service{Hub: f}
	for _, raw := range []string{`{}`, `{"machine_id":"fixture","paths":true}`} {
		if _, err := s.Call(context.Background(), "disk_ops_status", json.RawMessage(raw)); err == nil || f.calls != 0 {
			t.Fatal("invalid status called Hub", err)
		}
	}
	out, err := s.Call(context.Background(), "disk_ops_status", json.RawMessage(`{"machine_id":"fixture"}`))
	if err != nil || out.(map[string]any)["machine_id"] != "fixture" || f.calls != 1 {
		t.Fatal("status", err)
	}
}

func TestDiskStatusMCPProjectionExcludesPrivateEvidence(t *testing.T) {
	s := store.DiskOpsStatus{MachineID: "fixture", Mounts: []store.DiskMountUsage{{Mount: "/srv/private"}}, Skips: map[string]string{"/srv/private": "/srv/private"}, Ownership: map[string]string{"user": "/srv/private"}}
	e := &store.DiskSafeEnvelope{}
	e.Operation.Protections = []string{"/srv/private"}
	e.Summary.Host = "/srv/private"
	e.Summary.Disk.Mount = "/srv/private"
	e.Summary.Categories = map[string]maintenance.SummaryCategory{"uv": {Status: "skipped", Note: "/srv/private"}, "/srv/private": {Note: "/srv/private"}}
	s.LastSafeTier, s.Preview = e, e
	raw, err := json.Marshal(redactedDiskStatus(s))
	if err != nil || strings.Contains(string(raw), "/srv/private") || !strings.Contains(string(raw), "sha256:"+scriptcatalog.Digest([]byte("/srv/private"))) {
		t.Fatalf("unsafe projection: %s %v", raw, err)
	}
}

type fakeDeepReportHub struct{ fakeHub }

func (f *fakeDeepReportHub) DiskReport(context.Context, string, string, int) (store.DiskReportPage, error) {
	return store.DiskReportPage{Items: []diskreport.Item{{ID: "candidate", Category: "app-update-backups", PrivatePath: "/home/private-account/project/backup.bak", Confidence: "low", SuggestedAction: "investigate", OwnerApp: "private-account"}}, DiskReportSummary: store.DiskReportSummary{Report: diskreport.Report{Notices: []string{"/home/private-account"}}}}, nil
}
func TestDiskReportMCPDefensiveProjection(t *testing.T) {
	s := &Service{Hub: &fakeDeepReportHub{}}
	v, e := s.Call(context.Background(), "disk_report_get", json.RawMessage(`{"id":"report-fixture","limit":100}`))
	if e != nil {
		t.Fatal(e)
	}
	raw, _ := json.Marshal(v)
	if strings.Contains(string(raw), "private-account") || strings.Contains(string(raw), "private_path") {
		t.Fatal("MCP leaked private fields")
	}
	for _, args := range []string{`{"id":"report-fixture","limit":101}`, `{"id":"report-fixture","paths":true}`} {
		if _, e = s.Call(context.Background(), "disk_report_get", json.RawMessage(args)); e == nil {
			t.Fatal("invalid MCP args accepted")
		}
	}
}

type fakeDiskActionsHub struct {
	fakeHub
	calls int
}

func (f *fakeDiskActionsHub) DiskActionPreview(context.Context, store.DiskActionRequest) (store.DiskActionPreview, error) {
	f.calls++
	return store.DiskActionPreview{Items: []diskreport.Item{{ID: "candidate", PrivatePath: "/home/private-account/project/file", DisplayPath: "/home/private-account/project/file", OriginalParent: []uint64{1, 2}, Identity: diskreport.Identity{Dev: 1, Inode: 2}}}}, nil
}
func (f *fakeDiskActionsHub) DiskRestorePreview(c context.Context, _ store.DiskRestoreRequest) (store.DiskActionPreview, error) {
	return f.DiskActionPreview(c, store.DiskActionRequest{})
}
func (f *fakeDiskActionsHub) DiskActionDecide(context.Context, store.OpsApprovalDecisionRequest, string, bool) (store.OpsApprovalDecisionResult, error) {
	f.calls++
	return store.OpsApprovalDecisionResult{}, nil
}
func (f *fakeDiskActionsHub) DiskQuarantineList(context.Context, string) ([]store.DiskQuarantineItem, error) {
	f.calls++
	return []store.DiskQuarantineItem{{ItemID: "candidate", DisplayPath: "/home/private-account/project/file"}}, nil
}
func TestDiskActionsMCPBindingsAndDefensiveProjection(t *testing.T) {
	f := &fakeDiskActionsHub{}
	s := &Service{Hub: f}
	for name, args := range map[string]string{"disk_action_preview": `{"report_id":"report-fixture","report_digest":"sha256:` + strings.Repeat("a", 64) + `","action":"quarantine","item_ids":["candidate"],"reason":"review exact items"}`, "disk_restore_preview": `{"quarantine_id":"manifest-fixture","item_ids":["candidate"],"reason":"restore reviewed item"}`, "disk_quarantine_list": `{"machine_id":"machine-fixture"}`} {
		out, err := s.Call(context.Background(), name, json.RawMessage(args))
		if err != nil {
			t.Fatal(name, err)
		}
		raw, _ := json.Marshal(out)
		for _, secret := range []string{"private-account", "private_path", "original_parent", "\"inode\":2"} {
			if strings.Contains(string(raw), secret) {
				t.Fatalf("%s projection leaked %s", name, secret)
			}
		}
	}
	calls := f.calls
	for _, args := range []string{`{"id":"approval-fixture","decision":"approved","reason":"restore"}`, `{"id":"approval-fixture","decision":"rejected","reason":"restore","preview_digest":"sha256:` + strings.Repeat("a", 64) + `","idempotency_key":"fixture-key"}`} {
		if _, err := s.Call(context.Background(), "disk_restore_apply", json.RawMessage(args)); err == nil || f.calls != calls {
			t.Fatal("unbound restore called Hub", err)
		}
	}
	if _, err := s.Call(context.Background(), "disk_action_preview", json.RawMessage(`{"report_id":"report-fixture","paths":["/tmp/file"]}`)); err == nil || f.calls != calls {
		t.Fatal("unknown path field accepted")
	}
}

func TestDiskGrowthProjectionHidesMount(t *testing.T) {
	v := redactedDiskStatus(store.DiskOpsStatus{Growth: []store.DiskGrowth{{Mount: "/private-data", Known: true, GBPerHour: 12, WindowMinutes: 30, Samples: 4}}})
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "/private-data") || !strings.Contains(string(raw), `"gb_per_hour":12`) || !strings.Contains(string(raw), `"mount_digest"`) {
		t.Fatal("invalid growth projection")
	}
}
