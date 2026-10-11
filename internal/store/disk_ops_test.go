package store

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

func diskAdmin() AuditEntry {
	return AuditEntry{AuthSubject: "human-admin", AuthMethod: operatorauth.AuthMethodLocalAccountSession, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)}
}
func diskPolicyFixture(t *testing.T) (*Store, DiskPolicyRequest, DiskPolicyResult, time.Time) {
	t.Helper()
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.nowFn = func() time.Time { return now }
	s.ConfigureDiskOpsV2Writes(true)
	rev := int64(0)
	req := DiskPolicyRequest{ID: "disk-default", Body: mustScriptJSON(DefaultDiskPolicy()), ExpectedRevision: &rev, Reason: "review disk policy"}
	preview, err := s.DiskPolicyUpsert(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.ExpiresAt = preview.ExpiresAt
	req.PreviewDigest = preview.PreviewDigest
	out, err := s.DiskPolicyUpsert(req, true, "policy-create", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	return s, req, out, now
}
func TestDiskPolicyValidationAndCanonicalDigest(t *testing.T) {
	p := DefaultDiskPolicy()
	p.ProtectPaths = []string{"/data/models", "/data/repos"}
	_, raw, d, err := CanonicalDiskPolicy(mustScriptJSON(p))
	if err != nil {
		t.Fatal(err)
	}
	p.ProtectPaths = []string{"/data/repos", "/data/models"}
	_, other, od, err := CanonicalDiskPolicy(mustScriptJSON(p))
	if err != nil || string(raw) != string(other) || d != od {
		t.Fatal("noncanonical digest")
	}
	for _, mutate := range []func(*DiskPolicy){func(p *DiskPolicy) { p.QuarantineTTLDays = 6 }, func(p *DiskPolicy) { p.SafeTier.UserTmpMinDays = 9 }, func(p *DiskPolicy) { p.SafeTier.VarTmpMinDays = 13 }, func(p *DiskPolicy) { p.SafeTier.DockerMinHours = 167 }, func(p *DiskPolicy) { p.SafeTier.CargoMinDays = 29 }, func(p *DiskPolicy) { p.SafeTier.NPMMode = "clean-force" }, func(p *DiskPolicy) { p.SafeTier.UVMode = "force" }, func(p *DiskPolicy) { p.ScanBudgets.MaxItems = 501 }, func(p *DiskPolicy) { p.ScanBudgets.MaxEntries = 200001 }, func(p *DiskPolicy) { p.ScanBudgets.MaxSeconds = 601 }, func(p *DiskPolicy) { p.Thresholds.WarnPercent = 94 }, func(p *DiskPolicy) { p.ProtectPaths = []string{"/tmp/../credentials"} }, func(p *DiskPolicy) { p.ProtectPaths = []string{"relative"} }, func(p *DiskPolicy) { p.ProtectPaths = []string{"/tmp", "/tmp"} }} {
		bad := DefaultDiskPolicy()
		mutate(&bad)
		if _, _, _, err := CanonicalDiskPolicy(mustScriptJSON(bad)); err == nil {
			t.Fatalf("accepted unsafe policy: %+v", bad)
		}
	}
	for _, raw := range []string{`{"unknown":true}`, strings.Replace(string(mustScriptJSON(DefaultDiskPolicy())), `"npm_mode":"verify-only"`, `"npm_mode":"verify-only","force":true`, 1), string(mustScriptJSON(DefaultDiskPolicy())) + ` {}`} {
		if _, _, _, err := CanonicalDiskPolicy(json.RawMessage(raw)); err == nil {
			t.Fatal("accepted unknown fields/trailing JSON")
		}
	}
}
func TestDiskPolicyRevisionImmutabilityReplayAndOff(t *testing.T) {
	s, req, out, now := diskPolicyFixture(t)
	replay, err := s.DiskPolicyUpsert(req, true, "policy-create", diskAdmin())
	if err != nil || !replay.Replayed || replay.Policy.Revision != out.Policy.Revision {
		t.Fatalf("replay %+v %v", replay, err)
	}
	for _, stmt := range []string{`UPDATE ops_policies SET body='{}'`, `UPDATE ops_policies SET digest='wrong'`, `DELETE FROM ops_policies`} {
		if _, err := s.db.Exec(stmt); err == nil {
			t.Fatal("immutable policy changed")
		}
	}
	actor := diskAdmin()
	actor.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err = s.DiskPolicyUpsert(req, true, "policy-create", actor); err == nil {
		t.Fatal("token replay authorized")
	}
	req.Body = mustScriptJSON(DefaultDiskPolicy())
	rev := int64(1)
	req.ExpectedRevision = &rev
	preview, err := s.DiskPolicyUpsert(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	req.ExpiresAt = preview.ExpiresAt
	s.ConfigureDiskOpsV2Writes(false)
	if _, err = s.DiskPolicyUpsert(req, true, "policy-update", diskAdmin()); err == nil {
		t.Fatal("writes enabled by default")
	}
	s.ConfigureDiskOpsV2Writes(true)
	if _, err = s.DiskPolicyUpsert(req, true, "policy-update", diskAdmin()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.DiskPolicyUpsert(req, true, "stale", diskAdmin()); err == nil {
		t.Fatal("stale revision accepted")
	}
	list, err := s.DiskPolicies()
	if err != nil || len(list) != 2 || list[1].SupersededAt == nil {
		t.Fatalf("history %+v %v", list, err)
	}
	req.ExpectedRevision = new(int64)
	*req.ExpectedRevision = 2
	p, err := s.DiskPolicyUpsert(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = p.PreviewDigest
	req.ExpiresAt = p.ExpiresAt
	s.nowFn = func() time.Time { return now.Add(31 * time.Minute) }
	if _, err = s.DiskPolicyUpsert(req, true, "expired-preview", diskAdmin()); err == nil {
		t.Fatal("expired preview accepted")
	}
}
func approvalFixture(t *testing.T) (*Store, OpsApproval, time.Time) {
	t.Helper()
	s, _, policy, now := diskPolicyFixture(t)
	machine := mustEnroll(t, s, "example-device", now)
	a, err := s.CreateOpsApproval(OpsApproval{ID: "approval-1", MachineID: machine, Operation: "quarantine", PolicyID: policy.Policy.ID, PolicyRevision: policy.Policy.Revision, PolicyDigest: policy.Policy.Digest, ItemDigest: "sha256:" + strings.Repeat("a", 64)}, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	return s, a, now
}
func TestOpsApprovalHumanOnlyExpiryRevocationAndSummary(t *testing.T) {
	s, a, now := approvalFixture(t)
	for _, actor := range []AuditEntry{{AuthSubject: "optional-agent", AuthMethod: operatorauth.AuthMethodServiceToken, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)}, {AuthSubject: "human-admin", AuthCapability: "admin"}, {AuthSubject: "human-admin", AuthMethod: operatorauth.AuthMethodLocalAccountSession, AuthCapability: "operate", AuthDecision: string(operatorauth.Authorized)}} {
		if _, err := s.DecideOpsApproval(a, true, actor); err == nil {
			t.Fatal("nonhuman approval allowed")
		}
	}
	wrong := a
	wrong.ItemDigest = "sha256:" + strings.Repeat("b", 64)
	if _, err := s.DecideOpsApproval(wrong, true, diskAdmin()); err == nil {
		t.Fatal("wrong manifest approved")
	}
	summary, err := s.ApprovalsSummaryContext(context.Background(), "", now)
	if err != nil || summary.DiskOps.Pending != 1 || summary.DiskOps.OldestPendingAgeSeconds == nil {
		t.Fatalf("summary %+v %v", summary.DiskOps, err)
	}
	s.nowFn = func() time.Time { return now.Add(30 * time.Minute) }
	if _, err := s.DecideOpsApproval(a, true, diskAdmin()); err == nil {
		t.Fatal("deadline inclusive approval")
	}
	list, err := s.OpsApprovals(now.Add(30 * time.Minute))
	if err != nil || list[0].State != "expired" {
		t.Fatalf("expiry %+v %v", list, err)
	}
	s, a, now = approvalFixture(t)
	a, err = s.DecideOpsApproval(a, true, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	rev := int64(1)
	req := DiskPolicyRequest{ID: a.PolicyID, Body: mustScriptJSON(DefaultDiskPolicy()), ExpectedRevision: &rev, Reason: "revoke prior revision"}
	p, err := s.DiskPolicyUpsert(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = p.PreviewDigest
	req.ExpiresAt = p.ExpiresAt
	if _, err = s.DiskPolicyUpsert(req, true, "revoke", diskAdmin()); err != nil {
		t.Fatal(err)
	}
	list, err = s.OpsApprovals(now)
	if err != nil || list[0].State != "rejected" {
		t.Fatalf("revocation %+v %v", list, err)
	}
}
func TestOpsApprovalConsumeOnceAtomicReplay(t *testing.T) {
	s, a, now := approvalFixture(t)
	var err error
	a, err = s.DecideOpsApproval(a, true, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	factory := func(tx dbTx, a OpsApproval) (string, error) {
		calls++
		e, _ := scriptcatalog.Lookup("fleet-probe-v1")
		spec := scriptcatalog.Spec{Kind: scriptcatalog.Kind, ScriptID: e.ID, ScriptSHA256: e.SHA256, ExecutionMode: e.Mode, Args: json.RawMessage(`{}`)}
		raw := mustScriptJSON(spec)
		desired, rev, err := createDesiredStateTx(tx, "machine", a.MachineID, scriptcatalog.Kind, e.ID, string(raw), "operator:human-admin", now)
		if err != nil {
			return "", err
		}
		return createManagedJobTx(tx, a.MachineID, desired, rev, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(raw)}, now)
	}
	fail := func(tx dbTx, a OpsApproval) (string, error) {
		if _, err := factory(tx, a); err != nil {
			return "", err
		}
		return "", errors.New("injected job failure")
	}
	if _, err = s.consumeOpsApproval(a, "consume", diskAdmin(), fail); err == nil {
		t.Fatal("failure committed")
	}
	var count int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("job not rolled back")
	}
	out, err := s.consumeOpsApproval(a, "consume", diskAdmin(), factory)
	if err != nil || out.State != "consumed" || out.JobID == "" {
		t.Fatalf("consume %+v %v", out, err)
	}
	replay, err := s.consumeOpsApproval(a, "consume", diskAdmin(), factory)
	if err != nil || replay.JobID != out.JobID || calls != 2 {
		t.Fatalf("replay %+v %v calls=%d", replay, err, calls)
	}
	if _, err = s.consumeOpsApproval(a, "different-key", diskAdmin(), factory); err == nil {
		t.Fatal("consumed twice")
	}
	actor := diskAdmin()
	actor.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err = s.consumeOpsApproval(a, "consume", actor, factory); err == nil {
		t.Fatal("unauthorized replay")
	}
	wrong := a
	wrong.ItemDigest = "sha256:" + strings.Repeat("c", 64)
	if _, err = s.consumeOpsApproval(wrong, "consume", diskAdmin(), factory); err == nil {
		t.Fatal("conflicting retry")
	}
}
func TestDiskOpsCapabilityExactCheckinAndParsing(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	id := mustEnroll(t, s, "example-device", now)
	var c model.Checkin
	if err := json.Unmarshal([]byte(`{"disk_ops_v2":true}`), &c); err != nil || !c.DiskOpsV2 {
		t.Fatal("capability parsing")
	}
	if err := json.Unmarshal([]byte(`{"disk_ops_v2":"true"}`), &c); err == nil {
		t.Fatal("nonboolean capability")
	}
	c = healthyCheckin(now)
	c.DiskOpsV2 = true
	if err := s.RecordCheckin(id, c, now); err != nil {
		t.Fatal(err)
	}
	r, err := s.AgentReadiness(id)
	if err != nil || r.DiskOpsV2 == nil || !*r.DiskOpsV2 {
		t.Fatal("missing support", err)
	}
	c = healthyCheckin(now.Add(time.Minute))
	c.ScriptV1 = true
	if err := s.RecordCheckin(id, c, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	r, err = s.AgentReadiness(id)
	if err != nil || r.DiskOpsV2 != nil {
		t.Fatal("inherited stale support", err)
	}
	c.DiskOpsV2 = true
	if err := s.RecordCheckin(id, c, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	c.DiskOpsV2 = false
	if err := s.RecordCheckin(id, c, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	r, err = s.AgentReadiness(id)
	if err != nil || r.DiskOpsV2 != nil {
		t.Fatal("replay did not withdraw capability", err)
	}
}
func TestDiskOpsMigrationReopenDefaultOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Simulate a Phase 1 ledger: preserve machine data while removing only the
	// new empty tables in this disposable fixture, then reopen for migration.
	now := time.Now().UTC().Truncate(time.Second)
	id := mustEnroll(t, s, "example-device", now)
	if _, err = s.db.Exec(`DROP TABLE ops_approvals; DROP TABLE ops_policies`); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var retained int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM machine_registry WHERE machine_id=?`, id).Scan(&retained); err != nil || retained != 1 {
		t.Fatal("migration lost existing machine", err)
	}
	if s.diskOpsV2Writes.Load() {
		t.Fatal("writes default on")
	}
	if _, err = s.DiskPolicies(); err != nil {
		t.Fatal(err)
	}
	if _, err = s.OpsApprovals(time.Now()); err != nil {
		t.Fatal(err)
	}
}

func TestDiskPolicyProtectionCannotBeRemoved(t *testing.T) {
	p := DefaultDiskPolicy()
	rules := p.Protections()
	if len(rules.BuiltInNames) < 20 || len(rules.ProtectedClasses) < 8 {
		t.Fatal("missing immutable protections")
	}
	rules.BuiltInNames[0] = "changed"
	rules.ProtectedClasses[0] = "changed"
	fresh := p.Protections()
	if fresh.BuiltInNames[0] == "changed" || fresh.ProtectedClasses[0] == "changed" {
		t.Fatal("caller removed built-in protection")
	}
	raw := strings.Replace(string(mustScriptJSON(p)), `"schema_version":1`, `"schema_version":1,"built_in_names":[]`, 1)
	if _, _, _, err := CanonicalDiskPolicy(json.RawMessage(raw)); err == nil {
		t.Fatal("policy can override built-ins")
	}
}

func TestDiskPolicySupersessionRejectsQueuedConsumedJob(t *testing.T) {
	s, a, now := approvalFixture(t)
	a, err := s.DecideOpsApproval(a, true, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	create := func(tx dbTx, a OpsApproval) (string, error) {
		e, _ := scriptcatalog.Lookup("fleet-probe-v1")
		raw := mustScriptJSON(scriptcatalog.Spec{Kind: scriptcatalog.Kind, ScriptID: e.ID, ScriptSHA256: e.SHA256, ExecutionMode: e.Mode, Args: json.RawMessage(`{}`)})
		d, r, err := createDesiredStateTx(tx, "machine", a.MachineID, scriptcatalog.Kind, e.ID, string(raw), "operator:human-admin", now)
		if err != nil {
			return "", err
		}
		return createManagedJobTx(tx, a.MachineID, d, r, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(raw)}, now)
	}
	consumed, err := s.consumeOpsApproval(a, "consume", diskAdmin(), create)
	if err != nil {
		t.Fatal(err)
	}
	rev := int64(1)
	req := DiskPolicyRequest{ID: a.PolicyID, Body: mustScriptJSON(DefaultDiskPolicy()), ExpectedRevision: &rev, Reason: "revoke queued work"}
	p, err := s.DiskPolicyUpsert(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = p.PreviewDigest
	req.ExpiresAt = p.ExpiresAt
	if _, err = s.DiskPolicyUpsert(req, true, "revoke", diskAdmin()); err != nil {
		t.Fatal(err)
	}
	var state string
	if err = s.rdb.QueryRow(`SELECT state FROM jobs WHERE job_id=?`, consumed.JobID).Scan(&state); err != nil || state != "rejected" {
		t.Fatalf("queued work not revoked: %s %v", state, err)
	}
}

func TestOpsApprovalAuditFailureRollsBackConsumption(t *testing.T) {
	s, a, now := approvalFixture(t)
	a, err := s.DecideOpsApproval(a, true, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`CREATE TRIGGER fail_disk_consume_audit BEFORE INSERT ON audit_log WHEN NEW.action='ops-approval' AND NEW.outcome='ok' BEGIN SELECT RAISE(ABORT,'injected audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	create := func(tx dbTx, a OpsApproval) (string, error) {
		e, _ := scriptcatalog.Lookup("fleet-probe-v1")
		raw := mustScriptJSON(scriptcatalog.Spec{Kind: scriptcatalog.Kind, ScriptID: e.ID, ScriptSHA256: e.SHA256, ExecutionMode: e.Mode, Args: json.RawMessage(`{}`)})
		d, r, err := createDesiredStateTx(tx, "machine", a.MachineID, scriptcatalog.Kind, e.ID, string(raw), "operator:human-admin", now)
		if err != nil {
			return "", err
		}
		return createManagedJobTx(tx, a.MachineID, d, r, NewJob{ArtifactDigest: "sha256:" + scriptcatalog.Digest(raw)}, now)
	}
	if _, err = s.consumeOpsApproval(a, "audit-failure", diskAdmin(), create); err == nil {
		t.Fatal("unaudited consumption committed")
	}
	var state string
	if err = s.rdb.QueryRow(`SELECT state FROM ops_approvals WHERE id=?`, a.ID).Scan(&state); err != nil || state != "approved" {
		t.Fatal("consume not rolled back", state, err)
	}
	for _, query := range []string{`SELECT COUNT(*) FROM jobs`, `SELECT COUNT(*) FROM operator_idempotency WHERE idempotency_key='audit-failure'`} {
		var n int
		if err = s.rdb.QueryRow(query).Scan(&n); err != nil || n != 0 {
			t.Fatal("transaction residue", n, err)
		}
	}
}
