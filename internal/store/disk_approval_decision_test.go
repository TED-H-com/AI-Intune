package store

import (
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/totp"
	"strings"
	"testing"
	"time"
)

func TestDiskApprovalDecisionPreviewApplyBindingsAndReplay(t *testing.T) {
	s, a, _ := approvalFixture(t)
	req := OpsApprovalDecisionRequest{ID: a.ID, Decision: "approved", Reason: "review the exact manifest"}
	p, err := s.OpsApprovalDecision(req, false, "", diskAdmin())
	if err != nil || p.Approval.State != "pending" || p.Request.PolicyRevision != a.PolicyRevision {
		t.Fatal(p, err)
	}
	var state string
	s.rdb.QueryRow(`SELECT state FROM ops_approvals WHERE id=?`, a.ID).Scan(&state)
	if state != "pending" {
		t.Fatal("preview decided approval")
	}
	for _, mutate := range []func(*OpsApprovalDecisionRequest){func(r *OpsApprovalDecisionRequest) { r.PolicyRevision++ }, func(r *OpsApprovalDecisionRequest) { r.PolicyDigest = "sha256:" + strings.Repeat("b", 64) }, func(r *OpsApprovalDecisionRequest) { r.ItemDigest = "sha256:" + strings.Repeat("b", 64) }, func(r *OpsApprovalDecisionRequest) { r.Deadline = r.Deadline.Add(time.Second) }, func(r *OpsApprovalDecisionRequest) { r.Decision = "rejected" }, func(r *OpsApprovalDecisionRequest) { r.Reason = "changed reason" }, func(r *OpsApprovalDecisionRequest) { r.PreviewDigest = "sha256:" + strings.Repeat("b", 64) }} {
		bad := p.Request
		mutate(&bad)
		if _, err = s.OpsApprovalDecision(bad, true, "decision", diskAdmin()); err == nil {
			t.Fatal("tampered approval accepted", bad)
		}
	}
	out, err := s.OpsApprovalDecision(p.Request, true, "decision", diskAdmin())
	if err != nil || out.Approval.State != "approved" {
		t.Fatal(out, err)
	}
	retry, err := s.OpsApprovalDecision(p.Request, true, "decision", diskAdmin())
	if err != nil || !retry.Replayed || retry.Approval.DecisionActor != out.Approval.DecisionActor {
		t.Fatal(retry, err)
	}
	token := diskAdmin()
	token.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err = s.OpsApprovalDecision(p.Request, true, "decision", token); err == nil {
		t.Fatal("unauthorized replay")
	}
	if _, err = s.OpsApprovalDecision(p.Request, true, "new-key", diskAdmin()); err == nil {
		t.Fatal("decided twice")
	}
}
func TestDiskApprovalDecisionExpiryRevocationAndDefaultOff(t *testing.T) {
	s, a, now := approvalFixture(t)
	req := OpsApprovalDecisionRequest{ID: a.ID, Decision: "rejected", Reason: "review manifest"}
	p, err := s.OpsApprovalDecision(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureDiskOpsV2Writes(false)
	if _, err = s.OpsApprovalDecision(p.Request, true, "decision", diskAdmin()); err == nil {
		t.Fatal("writes enabled")
	}
	s.ConfigureDiskOpsV2Writes(true)
	s.nowFn = func() time.Time { return now.Add(30 * time.Minute) }
	if _, err = s.OpsApprovalDecision(p.Request, true, "decision", diskAdmin()); err == nil {
		t.Fatal("expired binding accepted")
	}
	items, err := s.OpsApprovalsFiltered("expired", a.MachineID, "quarantine", now.Add(30*time.Minute))
	if err != nil || len(items) != 1 || items[0].State != "expired" {
		t.Fatal("expiry filter", items, err)
	}
	s.nowFn = func() time.Time { return now }
	if _, err = s.db.Exec(`UPDATE ops_policies SET superseded_at=? WHERE id=?`, fmtTime(now), a.PolicyID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.OpsApprovalDecision(p.Request, true, "decision", diskAdmin()); err == nil {
		t.Fatal("revoked policy accepted")
	}
}
func TestDiskAdminReauthenticationPasswordMFAAndHumanOnly(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	s.nowFn = func() time.Time { return now }
	account, err := s.CreateFirstAdmin("example-admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	actor := diskAdmin()
	actor.AuthSubject = "local-user:" + account.AccountID
	actor.SourceAddr = "192.0.2.10"
	if err = s.ReauthenticateDiskAdmin(actor, "incorrect", "", false); err == nil {
		t.Fatal("incorrect password accepted")
	}
	if err = s.ReauthenticateDiskAdmin(actor, testAdminPassword, "", true); err == nil {
		t.Fatal("required MFA ignored")
	}
	if err = s.ReauthenticateDiskAdmin(actor, testAdminPassword, "", false); err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, err := totp.Code(secret, now.Unix()/30)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.ConfirmTOTP(account.AccountID, code); err != nil {
		t.Fatal(err)
	}
	if err = s.ReauthenticateDiskAdmin(actor, testAdminPassword, "", false); err == nil {
		t.Fatal("enrolled MFA bypassed under opt-out")
	}
	now = now.Add(30 * time.Second)
	code, _ = totp.Code(secret, now.Unix()/30)
	if err = s.ReauthenticateDiskAdmin(actor, testAdminPassword, code, true); err != nil {
		t.Fatal(err)
	}
	actor.AuthMethod = operatorauth.AuthMethodServiceToken
	if err = s.ReauthenticateDiskAdmin(actor, testAdminPassword, code, false); err == nil {
		t.Fatal("token reauthenticated")
	}
	var count int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE ? OR detail LIKE ?`, "%"+testAdminPassword+"%", "%"+secret+"%").Scan(&count); err != nil || count != 0 {
		t.Fatal("credentials in audit")
	}
}

func TestDiskApprovalDecisionReasonStoredSanitizedAndBound(t *testing.T) {
	s, a, _ := approvalFixture(t)
	req := OpsApprovalDecisionRequest{ID: a.ID, Decision: "approved", Reason: " reviewed manifest safely "}
	p, err := s.OpsApprovalDecision(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if p.Request.Reason != "reviewed manifest safely" {
		t.Fatal("control characters retained", p.Request.Reason)
	}
	changed := p.Request
	changed.Reason = "different reason"
	if _, err = s.OpsApprovalDecision(changed, true, "reason-decision", diskAdmin()); err == nil {
		t.Fatal("changed reason accepted")
	}
	out, err := s.OpsApprovalDecision(p.Request, true, "reason-decision", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	stored, err := s.OpsApproval(a.ID, s.now())
	if err != nil || stored.DecisionReason != p.Request.Reason || out.Approval.DecisionReason != stored.DecisionReason {
		t.Fatal(stored, err)
	}
	var detail string
	if err = s.db.QueryRow(`SELECT detail FROM audit_log WHERE action=? AND idempotency_key=? ORDER BY audit_id DESC LIMIT 1`, AuditOpsApproval, "reason-decision").Scan(&detail); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(detail, `"decision_reason":"reviewed manifest safely"`) {
		t.Fatal("reason absent from success audit", detail)
	}
	req.Reason = strings.Repeat("a", 501)
	if _, err = s.OpsApprovalDecision(req, false, "", diskAdmin()); err == nil {
		t.Fatal("unbounded reason")
	}
	req.Reason = "\x00\n\t"
	if _, err = s.OpsApprovalDecision(req, false, "", diskAdmin()); err == nil {
		t.Fatal("empty sanitized reason")
	}
}

func TestDiskPolicyRevisionRejectsUsagePolicy(t *testing.T) {
	s, req, disk, _ := diskPolicyFixture(t)
	policy := DefaultUsagePolicy()
	preview, err := UsagePolicyPreviewDigest("usage-default", 0, policy)
	if err != nil {
		t.Fatal(err)
	}
	usage, err := s.PublishUsagePolicy("usage-default", 0, policy, preview, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.DiskPolicyRevision(usage.ID, usage.Revision); err == nil {
		t.Fatal("usage policy returned as disk policy revision")
	} else if e, ok := err.(*OperatorRequestError); !ok || e.Code != OperatorCodeMaintenanceNotFound {
		t.Fatalf("expected policy revision not found, got %v", err)
	}
	got, err := s.DiskPolicyRevision(req.ID, disk.Policy.Revision)
	if err != nil || got.Kind != "disk" || got.Digest != disk.Policy.Digest {
		t.Fatalf("disk policy=%+v: %v", got, err)
	}
}
