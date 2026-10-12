package web

import (
	"bytes"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

const diskFixturePassword = "example fixture password 123!"

func diskWebPrincipal(admin, local bool, id string) operatorauth.Principal {
	names, _ := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	grants := operatorauth.CapabilityNames{View: names.View}
	cap := names.View
	if admin {
		grants.Admin = names.Admin
		cap = names.Admin
	}
	p := operatorauth.Principal{SourceAddr: "192.0.2.10", NodeStableID: "fixture-node", DeviceName: "browser", TailnetUserID: "fixture-human", TailnetUserLogin: "example-admin", AuthMethod: operatorauth.AuthMethodLocalAPI, AuthorizedCapability: cap, GrantedCapabilities: grants}
	if local {
		p.AuthMethod = operatorauth.AuthMethodLocalAccountSession
		p.TailnetUserID = "local:" + id
	}
	return p
}
func diskWebRequest(t *testing.T, s *Server, method, path string, form url.Values, p operatorauth.Principal, optout bool) *httptest.ResponseRecorder {
	t.Helper()
	mux := http.NewServeMux()
	s.Routes(mux)
	r := httptest.NewRequest(method, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r = operatorauth.WithPrincipal(r, p)
	if optout {
		r = WithMFAEnforcementDisabled(r)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}
func diskWebEditForm() url.Values {
	p := store.DefaultDiskPolicy()
	return url.Values{"id": {"disk-default"}, "expected_revision": {"0"}, "user_tmp_min_days": {strconv.Itoa(p.SafeTier.UserTmpMinDays)}, "var_tmp_min_days": {strconv.Itoa(p.SafeTier.VarTmpMinDays)}, "docker_min_hours": {strconv.Itoa(p.SafeTier.DockerMinHours)}, "journald_max_mib": {strconv.Itoa(p.SafeTier.JournaldMaxMiB)}, "cargo_min_days": {strconv.Itoa(p.SafeTier.CargoMinDays)}, "warn_percent": {strconv.Itoa(p.Thresholds.WarnPercent)}, "critical_percent": {strconv.Itoa(p.Thresholds.CriticalPercent)}, "deep_report_above_percent": {strconv.Itoa(p.Thresholds.DeepReportAbovePercent)}, "max_items": {strconv.Itoa(p.ScanBudgets.MaxItems)}, "max_entries": {strconv.Itoa(p.ScanBudgets.MaxEntries)}, "max_seconds": {strconv.Itoa(p.ScanBudgets.MaxSeconds)}, "protect_paths": {"/srv/data"}, "reason": {"review safe defaults"}}
}
func diskWebHidden(t *testing.T, body string, names ...string) url.Values {
	t.Helper()
	out := url.Values{}
	for _, name := range names {
		out.Set(name, html.UnescapeString(hiddenFormValue(t, body, name)))
	}
	return out
}

var diskPolicyHidden = []string{"id", "body", "expected_revision", "expires_at", "preview_digest", "reason", "idempotency_key"}
var diskDecisionHidden = []string{"id", "decision", "policy_revision", "policy_digest", "item_digest", "deadline", "reason", "preview_digest", "idempotency_key"}

func createDiskWebPolicy(t *testing.T, s *Server, st *store.Store) store.OpsPolicy {
	t.Helper()
	st.ConfigureDiskOpsV2Writes(true)
	p := diskWebPrincipal(true, false, "")
	w := diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", diskWebEditForm(), p, false)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	form := diskWebHidden(t, w.Body.String(), diskPolicyHidden...)
	form.Set("confirm_id", "disk-default")
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", form, p, false)
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	policy, err := s.operator.DiskPolicy("disk-default")
	if err != nil {
		t.Fatal(err)
	}
	return policy
}
func createDiskWebApproval(t *testing.T, s *Server, st *store.Store, id string) store.OpsApproval {
	t.Helper()
	p, err := s.operator.DiskPolicy("disk-default")
	if err != nil {
		t.Fatal(err)
	}
	machine := onlineMachine(t, st, "example-device")
	a, err := s.operator.CreateDiskOpsApproval(store.OpsApproval{ID: id, MachineID: machine, Operation: "quarantine", PolicyID: p.ID, PolicyRevision: p.Revision, PolicyDigest: p.Digest, ItemDigest: "sha256:" + strings.Repeat("a", 64)}, operator.Actor{AuthSubject: "tailscale-user:fixture-human", AuthMethod: operatorauth.AuthMethodLocalAPI, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)})
	if err != nil {
		t.Fatal(err)
	}
	return a
}
func TestDiskPolicyWebHumanPreviewDiffApplyAndHistory(t *testing.T) {
	s, st := newServer(t)
	p := diskWebPrincipal(true, false, "")
	w := diskWebRequest(t, s, "GET", diskPoliciesBack, nil, p, false)
	for _, want := range []string{"Disk policies", "Disk writes are disabled", "Preview changes", "7 days", "No disk policies yet"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("missing %s", want)
		}
	}
	createDiskWebPolicy(t, s, st)
	w = diskWebRequest(t, s, "GET", diskPoliciesBack+"/disk-default", nil, p, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Canonical policy") || !strings.Contains(w.Body.String(), "sha256:") {
		t.Fatal(w.Body.String())
	}
	form := diskWebEditForm()
	form.Set("expected_revision", "1")
	form.Set("user_tmp_min_days", "15")
	form.Set("reason", "review <script>example</script> change")
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", form, p, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), ">10</td>") || !strings.Contains(w.Body.String(), ">15</td>") || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal("diff or escaping", w.Body.String())
	}
	apply := diskWebHidden(t, w.Body.String(), diskPolicyHidden...)
	apply.Set("confirm_id", "disk-default")
	for _, status := range []int{303, 303} {
		w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, false)
		if w.Code != status {
			t.Fatal(w.Body.String())
		}
	}
	policy, err := s.operator.DiskPolicy("disk-default")
	if err != nil || policy.Revision != 2 {
		t.Fatal(policy, err)
	}
	w = diskWebRequest(t, s, "GET", diskPoliciesBack+"/disk-default?revision=1", nil, p, false)
	if !strings.Contains(w.Body.String(), "immutable historical revision") || strings.Contains(w.Body.String(), "action=\"/tenant/disk-policies/preview\"") {
		t.Fatal("historical revision editable")
	}
}
func TestDiskPolicyWebLocalReauthenticationAndDisabledApply(t *testing.T) {
	s, st := newServer(t)
	account, err := st.CreateFirstAdmin("example-admin", diskFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	p := diskWebPrincipal(true, true, account.AccountID)
	w := diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", diskWebEditForm(), p, true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "current password") {
		t.Fatal(w.Body.String())
	}
	apply := diskWebHidden(t, w.Body.String(), diskPolicyHidden...)
	apply.Set("confirm_id", "disk-default")
	apply.Set("password", "incorrect fixture password")
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, true)
	if w.Code != 403 || strings.Contains(w.Body.String(), "incorrect fixture password") {
		t.Fatal("reauth failed open")
	}
	apply.Set("password", diskFixturePassword)
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, true)
	if w.Code != 412 {
		t.Fatal("writes not disabled", w.Code, w.Body.String())
	}
	st.ConfigureDiskOpsV2Writes(true)
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, false)
	if w.Code != 403 {
		t.Fatal("MFA requirement bypassed")
	}
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, true)
	if w.Code != 303 {
		t.Fatal(w.Body.String())
	}
	var leaked int
	if err = st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE detail LIKE ?`, "%"+diskFixturePassword+"%").Scan(&leaked); err != nil || leaked != 0 {
		t.Fatal("password reached audit")
	}
}
func TestDiskApprovalWebDecisionsBindingsFiltersAndViewOnly(t *testing.T) {
	s, st := newServer(t)
	createDiskWebPolicy(t, s, st)
	a := createDiskWebApproval(t, s, st, "approval-example")
	p := diskWebPrincipal(true, false, "")
	w := diskWebRequest(t, s, "GET", diskApprovalsBack+"?state=pending", nil, p, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "approval-example") || !strings.Contains(w.Body.String(), "Approve · preview") {
		t.Fatal(w.Body.String())
	}
	view := diskWebPrincipal(false, false, "")
	w = diskWebRequest(t, s, "GET", diskApprovalsBack, nil, view, false)
	if strings.Contains(w.Body.String(), "action=\"/tenant/approvals/preview\"") || strings.Contains(w.Body.String(), "href=\"/tenant/disk-policies\"") {
		t.Fatal("view showed admin mutations or navigation")
	}
	w = diskWebRequest(t, s, "POST", diskApprovalsBack+"/preview", url.Values{"id": {a.ID}, "decision": {"approved"}, "reason": {"review items"}}, view, false)
	if w.Code != 403 {
		t.Fatal("view approved")
	}
	for _, decision := range []string{"approved", "rejected"} {
		if decision == "rejected" {
			a = createDiskWebApproval(t, s, st, "approval-reject-example")
		}
		w = diskWebRequest(t, s, "POST", diskApprovalsBack+"/preview", url.Values{"id": {a.ID}, "decision": {decision}, "reason": {"review items"}}, p, false)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
		apply := diskWebHidden(t, w.Body.String(), diskDecisionHidden...)
		apply.Set("confirm_id", a.ID)
		altered := url.Values{}
		for k, v := range apply {
			altered[k] = append([]string{}, v...)
		}
		altered.Set("item_digest", "sha256:"+strings.Repeat("b", 64))
		w = diskWebRequest(t, s, "POST", diskApprovalsBack+"/apply", altered, p, false)
		if w.Code != 412 {
			t.Fatal("tampered binding accepted", w.Code)
		}
		for _, status := range []int{303, 303} {
			w = diskWebRequest(t, s, "POST", diskApprovalsBack+"/apply", apply, p, false)
			if w.Code != status {
				t.Fatal(w.Body.String())
			}
		}
		w = diskWebRequest(t, s, "GET", diskApprovalsBack+"?state="+decision, nil, p, false)
		if !strings.Contains(w.Body.String(), a.ID) || strings.Contains(w.Body.String(), "action=\"/tenant/approvals/preview\"") {
			t.Fatal("decision/filter mismatch")
		}
	}
	w = diskWebRequest(t, s, "GET", diskApprovalsBack+"?state=unexpected", nil, p, false)
	if w.Code != 400 {
		t.Fatal("unknown state accepted")
	}
}
func TestDiskWebRejectsUnknownDuplicateFieldsAndTokens(t *testing.T) {
	s, _ := newServer(t)
	p := diskWebPrincipal(true, false, "")
	form := diskWebEditForm()
	form.Set("unknown", "true")
	w := diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", form, p, false)
	if w.Code != 400 {
		t.Fatal("unknown field accepted")
	}
	form = diskWebEditForm()
	form.Add("id", "other")
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", form, p, false)
	if w.Code != 400 {
		t.Fatal("duplicate field accepted")
	}
	form = diskWebEditForm()
	p.AuthMethod = operatorauth.AuthMethodServiceToken
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", form, p, false)
	if w.Code != 403 {
		t.Fatal("token used human page")
	}
}

// TestDiskOpsScreenshotFixtures writes the exact shared templates with generic
// fixture data. ops/screenshots/phase2-disk.sh invokes it and renders with Chrome.
func TestDiskOpsScreenshotFixtures(t *testing.T) {
	dir := os.Getenv("CLAWCTL_SCREENSHOT_DIR")
	if dir == "" {
		t.Skip("set CLAWCTL_SCREENSHOT_DIR to export fixture HTML")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	s, st := newServer(t)
	policy := createDiskWebPolicy(t, s, st)
	now := time.Now().UTC().Truncate(time.Second)
	p := diskWebPrincipal(true, true, "fixture-account")
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", diskPoliciesBack, nil), p)
	items := []store.OpsApproval{}
	for _, state := range []string{"pending", "approved", "rejected", "expired", "consumed"} {
		a := store.OpsApproval{ID: "approval-" + state, State: state, Actor: "example-admin", MachineID: "example-machine-id", Operation: "quarantine", PolicyID: policy.ID, PolicyRevision: policy.Revision, PolicyDigest: policy.Digest, ItemDigest: "sha256:" + strings.Repeat("a", 64), CreatedAt: now, Deadline: now.Add(30 * time.Minute)}
		if state == "expired" {
			a.Deadline = now.Add(-time.Minute)
		}
		if state == "approved" || state == "rejected" || state == "consumed" {
			a.DecisionActor = "example-admin"
			a.DecisionReason = "reviewed the exact manifest"
		}
		if state == "consumed" {
			a.JobID = "example-job-id"
		}
		items = append(items, a)
	}
	req := store.DiskPolicyRequest{ID: policy.ID, ExpectedRevision: &policy.Revision, Reason: "retain older temporary files"}
	edit := store.DefaultDiskPolicy()
	edit.SafeTier.UserTmpMinDays = 15
	edit.ProtectPaths = []string{"/srv/data"}
	req.Body, _ = json.Marshal(edit)
	preview, err := s.operator.DiskPolicyUpsert(req, false, "", operator.Actor{AuthSubject: "local-user:fixture-account", AuthMethod: operatorauth.AuthMethodLocalAccountSession, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)})
	if err != nil {
		t.Fatal(err)
	}
	removalEdit := edit
	removalEdit.ProtectPaths = []string{}
	req.Body, _ = json.Marshal(removalEdit)
	req.Reason = "remove the configured data protection after review"
	removalPreview, e := s.operator.DiskPolicyUpsert(req, false, "", operator.Actor{AuthSubject: "local-user:fixture-account", AuthMethod: operatorauth.AuthMethodLocalAccountSession, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)})
	if e != nil {
		t.Fatal(e)
	}
	decision := store.OpsApprovalDecisionResult{Approval: items[0], Request: store.OpsApprovalDecisionRequest{ID: items[0].ID, Decision: "approved", PolicyRevision: policy.Revision, PolicyDigest: policy.Digest, ItemDigest: items[0].ItemDigest, Deadline: items[0].Deadline, Reason: "reviewed the exact item manifest"}, PreviewDigest: "sha256:" + strings.Repeat("b", 64)}
	fixtures := []struct {
		name, template string
		data           page
	}{
		{"disk-policies", "disk_policies.html", page{Title: "Disk policies", Nav: "tenant-disk-policies", DiskPolicies: &diskPoliciesPage{Items: []store.OpsPolicy{policy}, Selected: &policy, Canonical: string(policy.Body), Edit: edit, ID: policy.ID, ExpectedRevision: policy.Revision, ProtectPaths: "/srv/data", WritesEnabled: true}}},
		{"disk-policy-preview", "disk_policy_review.html", page{Title: "Review disk policy", Nav: "tenant-disk-policies", DiskPolicyReview: &diskPolicyReviewPage{Preview: preview, Changes: operator.DiskPolicyChanges(preview.PreviousBody, preview.Policy.Body), Body: string(preview.Policy.Body), Reason: "retain older temporary files", IdempotencyKey: "fixture-policy-key", WritesEnabled: true}}},
		{"approvals", "disk_approvals.html", page{Title: "Approvals", Nav: "tenant-approvals", DiskApprovals: &diskApprovalsPage{Items: items, WritesEnabled: true}}},
		{"disk-policy-removal-preview", "disk_policy_review.html", page{Title: "Review protection removal", Nav: "tenant-disk-policies", DiskPolicyReview: &diskPolicyReviewPage{Preview: removalPreview, Changes: operator.DiskPolicyChanges(removalPreview.PreviousBody, removalPreview.Policy.Body), Body: string(removalPreview.Policy.Body), Reason: req.Reason, IdempotencyKey: "fixture-removal-key", WritesEnabled: true}}},
		{"approval-preview", "disk_approval_review.html", page{Title: "Review approval decision", Nav: "tenant-approvals", DiskApprovalReview: &diskApprovalReviewPage{Preview: decision, IdempotencyKey: "fixture-decision-key", WritesEnabled: true}}},
		{"disk-policies-disabled", "disk_policies.html", page{Title: "Disk policies", Nav: "tenant-disk-policies", DiskPolicies: &diskPoliciesPage{Items: []store.OpsPolicy{}, Edit: store.DefaultDiskPolicy(), ID: "disk-default"}}},
	}
	for _, f := range fixtures {
		w := httptest.NewRecorder()
		s.render(w, r, f.template, f.data)
		body := w.Body.Bytes()
		if !bytes.Contains(body, []byte("</html>")) || bytes.Contains(body, []byte("<script")) {
			t.Fatal("incomplete or scripted fixture", f.name)
		}
		if err := os.WriteFile(filepath.Join(dir, f.name+".html"), body, 0644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestDiskPolicyWebRemovalConfirmation(t *testing.T) {
	s, st := newServer(t)
	policy := createDiskWebPolicy(t, s, st)
	p := diskWebPrincipal(true, false, "")
	form := diskWebEditForm()
	form.Set("expected_revision", strconv.FormatInt(policy.Revision, 10))
	form.Set("protect_paths", "")
	w := diskWebRequest(t, s, "POST", diskPoliciesBack+"/preview", form, p, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Remove protection: ") || !strings.Contains(w.Body.String(), `type="checkbox" name="acknowledge_removed_paths" value="/srv/data" required`) {
		t.Fatal("missing per-path acknowledgement", w.Code, w.Body.String())
	}
	apply := diskWebHidden(t, w.Body.String(), diskPolicyHidden...)
	apply.Set("confirm_id", policy.ID)
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, false)
	if w.Code != 412 {
		t.Fatal("unchecked removal accepted", w.Code, w.Body.String())
	}
	apply.Set("acknowledge_removed_paths", "/srv/other")
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, false)
	if w.Code != 412 {
		t.Fatal("wrong acknowledgement accepted", w.Code)
	}
	apply.Set("acknowledge_removed_paths", "/srv/data")
	w = diskWebRequest(t, s, "POST", diskPoliciesBack+"/apply", apply, p, false)
	if w.Code != 303 {
		t.Fatal("checked removal rejected", w.Code, w.Body.String())
	}
}
