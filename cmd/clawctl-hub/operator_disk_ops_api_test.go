package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/web"
)

func TestDiskOpsPolicyAPIFlagBindingsAndRead(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store, artifactsDir: f.artifactsDir}
	h.operatorRoutes(f.mux)
	rev := int64(0)
	req := store.DiskPolicyRequest{ID: "disk-default", Body: mustDiskOpsJSON(t, store.DefaultDiskPolicy()), ExpectedRevision: &rev, Reason: "review disk safety"}
	raw := mustDiskOpsJSON(t, req)
	rec := diskOpsAdminRequest(t, f.mux, "/v1/operator/disk-ops/policies/preview", "", string(raw))
	if rec.Code != 200 {
		t.Fatalf("preview %d %s", rec.Code, rec.Body.String())
	}
	var out store.DiskPolicyResult
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = out.PreviewDigest
	req.ExpiresAt = out.ExpiresAt
	rec = diskOpsAdminRequest(t, f.mux, "/v1/operator/disk-ops/policies", "disk-create", string(mustDiskOpsJSON(t, req)))
	if rec.Code != 412 {
		t.Fatalf("default off %d %s", rec.Code, rec.Body.String())
	}
	// The process config enables the authoritative store gate.
	f.store.ConfigureDiskOpsV2Writes(true)
	for _, status := range []int{201, 200} {
		rec = diskOpsAdminRequest(t, f.mux, "/v1/operator/disk-ops/policies", "disk-create", string(mustDiskOpsJSON(t, req)))
		if rec.Code != status {
			t.Fatalf("apply %d %s", rec.Code, rec.Body.String())
		}
	}
	assertDiskJSONLocalDenied(t, f.mux, "/v1/operator/disk-ops/policies", "disk-create", string(mustDiskOpsJSON(t, req)))
	for _, path := range []string{"/v1/operator/disk-ops/policies", "/v1/operator/disk-ops/policies/disk-default", "/v1/operator/disk-ops/approvals"} {
		r := verifiedOperatorRequest(httptest.NewRequest("GET", path, nil), operatorauth.View)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("read %d %s", w.Code, w.Body.String())
		}
	}
	req.PreviewDigest = "sha256:" + strings.Repeat("b", 64)
	rec = diskOpsAdminRequest(t, f.mux, "/v1/operator/disk-ops/policies", "wrong-binding", string(mustDiskOpsJSON(t, req)))
	if rec.Code != 412 {
		t.Fatalf("binding %d %s", rec.Code, rec.Body.String())
	}
}
func mustDiskOpsJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func TestDiskOpsRoutesDenyTokenWritesAndPolicyPaths(t *testing.T) {
	for _, pattern := range []string{"GET /v1/operator/disk-ops/policies", "GET /v1/operator/disk-ops/policies/{id}", "POST /v1/operator/disk-ops/policies/preview", "POST /v1/operator/disk-ops/policies", "POST /v1/operator/disk-ops/ownership/preview", "POST /v1/operator/disk-ops/ownership", "POST /v1/operator/disk-ops/alerts/ack/preview", "POST /v1/operator/disk-ops/alerts/ack"} {
		p := operatorRoutePolicies[pattern]
		if p.ServiceTokenEligible != serviceIneligible {
			t.Fatalf("token eligible: %s", pattern)
		}
		if strings.HasPrefix(pattern, "POST") && p.Permission != operatorauth.Admin {
			t.Fatal("nonadmin mutation")
		}
	}
	f := observedOperatorFixture(t)
	for _, path := range []string{"/v1/operator/disk-ops/policies/preview", "/v1/operator/disk-ops/policies"} {
		r := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)), operatorauth.View)
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("view mutation %d", w.Code)
		}
	}
}

func diskOpsAdminRequest(t *testing.T, mux *http.ServeMux, path, key, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := operatorauth.WithPrincipal(httptest.NewRequest("POST", path, strings.NewReader(body)), operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAPI, TailnetUserID: "fixture-human", AuthorizedCapability: "example.com/cap/clawctl-admin", GrantedCapabilities: operatorauth.CapabilityNames{Admin: "example.com/cap/clawctl-admin"}})
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", key)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestDiskOpsPolicyHandlerDeniesServiceTokenBeforeReplay(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	h.operatorRoutes(f.mux)
	f.store.ConfigureDiskOpsV2Writes(true)
	rev := int64(0)
	body := store.DiskPolicyRequest{ID: "disk-default", Body: mustDiskOpsJSON(t, store.DefaultDiskPolicy()), ExpectedRevision: &rev, Reason: "review policy"}
	w := diskOpsAdminRequest(t, f.mux, "/v1/operator/disk-ops/policies/preview", "", string(mustDiskOpsJSON(t, body)))
	var p store.DiskPolicyResult
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
		t.Fatal(err)
	}
	body.PreviewDigest = p.PreviewDigest
	body.ExpiresAt = p.ExpiresAt
	raw := string(mustDiskOpsJSON(t, body))
	w = diskOpsAdminRequest(t, f.mux, "/v1/operator/disk-ops/policies", "policy-key", raw)
	if w.Code != 201 {
		t.Fatal(w.Body.String())
	}
	r := httptest.NewRequest("POST", "/v1/operator/disk-ops/policies", strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "policy-key")
	r = operatorauth.WithPrincipal(r, operatorauth.Principal{AuthMethod: operatorauth.AuthMethodServiceToken, TailnetUserID: "optional-agent", AuthorizedCapability: "admin"})
	w = httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != 403 || w.Header().Get("Idempotency-Replayed") != "" {
		t.Fatalf("token replay %d %s", w.Code, w.Body.String())
	}
}

func TestDiskWebRoutesEnforceCSRFAndLockedCSP(t *testing.T) {
	st := boundaryStore(t)
	ui, err := web.New(st, "")
	if err != nil {
		t.Fatal(err)
	}
	h := &hub{store: st}
	auth := &boundaryAuthorizer{allow: true}
	handler, err := newHubHTTPHandler(h, ui, auth, testOperatorAuthority)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/tenant/disk-policies/preview", "/tenant/disk-policies/apply", "/tenant/approvals/preview", "/tenant/approvals/apply", "/tenant/disk-alerts/ack/preview", "/tenant/disk-alerts/ack", "/machines/example-id/disk/ownership"} {
		r := newBoundaryRequest("POST", path, strings.NewReader("id=example-id"))
		r.RemoteAddr = "100.100.10.20:4321"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Sec-Fetch-Site", "cross-site")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 403 || strings.Contains(w.Body.String(), "Invalid form") {
			t.Fatalf("CSRF reached form handler %d %s", w.Code, w.Body.String())
		}
		if strings.Contains(w.Header().Get("Content-Security-Policy"), "script-src 'self' 'unsafe-inline'") {
			t.Fatal("inline scripts allowed")
		}
	}
	for _, path := range []string{"/tenant/disk-policies", "/tenant/approvals"} {
		r := newBoundaryRequest("GET", path, nil)
		r.RemoteAddr = "100.100.10.20:4321"
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(strings.ReplaceAll(w.Body.String(), "<script data-audit-reason>", ""), "<script") {
			t.Fatalf("render/CSP %d %s", w.Code, w.Body.String())
		}
	}
	var n int
	if err = st.DB().QueryRow(`SELECT COUNT(*) FROM ops_policies`).Scan(&n); err != nil || n != 0 {
		t.Fatal("cross-site mutation changed policies")
	}
}

func TestDiskApprovalDecisionJSONPreviewApplyReplay(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	h.operatorRoutes(f.mux)
	f.store.ConfigureDiskOpsV2Writes(true)
	audit := store.AuditEntry{AuthSubject: "human-admin", AuthMethod: operatorauth.AuthMethodLocalAccountSession, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)}
	rev := int64(0)
	policyReq := store.DiskPolicyRequest{ID: "disk-default", ExpectedRevision: &rev, Body: mustDiskOpsJSON(t, store.DefaultDiskPolicy()), Reason: "review safety"}
	preview, err := f.store.DiskPolicyUpsert(policyReq, false, "", audit)
	if err != nil {
		t.Fatal(err)
	}
	policyReq.PreviewDigest = preview.PreviewDigest
	policyReq.ExpiresAt = preview.ExpiresAt
	policy, err := f.store.DiskPolicyUpsert(policyReq, true, "fixture-policy", audit)
	if err != nil {
		t.Fatal(err)
	}
	approval, err := f.store.CreateOpsApproval(store.OpsApproval{ID: "example-approval", MachineID: f.machine.id, Operation: "quarantine", PolicyID: policy.Policy.ID, PolicyRevision: policy.Policy.Revision, PolicyDigest: policy.Policy.Digest, ItemDigest: "sha256:" + strings.Repeat("a", 64)}, audit)
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/operator/disk-ops/approvals/" + approval.ID + "/decision"
	request := store.OpsApprovalDecisionRequest{ID: approval.ID, Decision: "approved", Reason: "reviewed manifest"}
	w := diskOpsAdminRequest(t, f.mux, path+"/preview", "", string(mustDiskOpsJSON(t, request)))
	if w.Code != 200 {
		t.Fatalf("preview %d %s", w.Code, w.Body.String())
	}
	var receipt store.OpsApprovalDecisionResult
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	request = receipt.Request
	wrong := request
	wrong.ItemDigest = "sha256:" + strings.Repeat("b", 64)
	w = diskOpsAdminRequest(t, f.mux, path, "wrong-binding", string(mustDiskOpsJSON(t, wrong)))
	if w.Code != 412 {
		t.Fatalf("tampered %d %s", w.Code, w.Body.String())
	}
	raw := string(mustDiskOpsJSON(t, request))
	for _, status := range []int{201, 200} {
		w = diskOpsAdminRequest(t, f.mux, path, "approval-decision", raw)
		if w.Code != status {
			t.Fatalf("apply %d %s", w.Code, w.Body.String())
		}
	}
	assertDiskJSONLocalDenied(t, f.mux, path, "approval-decision", raw)
	r := httptest.NewRequest("POST", path, strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Idempotency-Key", "approval-decision")
	r = operatorauth.WithPrincipal(r, operatorauth.Principal{AuthMethod: operatorauth.AuthMethodServiceToken, TailnetUserID: "optional-agent", AuthorizedCapability: "admin"})
	w = httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != 403 || w.Header().Get("Idempotency-Replayed") != "" {
		t.Fatal("token received decision replay", w.Code)
	}
}

func assertDiskJSONLocalDenied(t *testing.T, mux *http.ServeMux, path, key, body string) {
	t.Helper()
	for _, retryKey := range []string{key, "fresh-key-no-receipt"} {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", retryKey)
		r = operatorauth.WithPrincipal(r, operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, TailnetUserID: "local:fixture-account", AuthorizedCapability: "example.com/cap/clawctl-admin", GrantedCapabilities: operatorauth.CapabilityNames{Admin: "example.com/cap/clawctl-admin"}})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 403 || w.Header().Get("Idempotency-Replayed") != "" {
			t.Fatalf("local session bypassed fresh JSON authorization: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestDiskJSONFreshHumanGatePrecedesLedgerLookup(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	h.operatorRoutes(f.mux)
	f.store.ConfigureDiskOpsV2Writes(true)
	if _, err := f.store.DB().Exec(`DROP TABLE operator_idempotency`); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/v1/operator/disk-ops/policies", "/v1/operator/disk-ops/approvals/example-approval/decision", "/v1/operator/disk-ops/actions/preview", "/v1/operator/disk-ops/actions/decide", "/v1/operator/disk-ops/restores/preview", "/v1/operator/disk-ops/restores", "/v1/operator/disk-ops/ownership", "/v1/operator/disk-ops/alerts/ack"} {
		// A missing receipt table would fail any attempted lookup. Local sessions
		// must instead fail the transport authorization gate, even on a retry.
		assertDiskJSONLocalDenied(t, f.mux, path, "existing-retry-key", `{"id":"example-approval","decision":"approved","reason":"reviewed manifest"}`)
	}
}

func TestDiskOpsStatusAPIViewAndQueryContract(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	h.operatorRoutes(f.mux)
	r := verifiedOperatorRequest(httptest.NewRequest("GET", "/v1/operator/disk-ops/status/"+f.machine.id, nil), operatorauth.View)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	var status store.DiskOpsStatus
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &status) != nil || status.MachineID != f.machine.id || status.Thresholds.WarnPercent != 85 || status.Thresholds.CriticalPercent != 93 {
		t.Fatal("status", w.Code, w.Body.String())
	}
	// Fixture target identity is immutable; the status route reports unknown
	// machines as a typed rejection and rejects query widening.
	for _, path := range []string{"/v1/operator/disk-ops/status/missing", "/v1/operator/disk-ops/status/missing?paths=true"} {
		r := verifiedOperatorRequest(httptest.NewRequest("GET", path, nil), operatorauth.View)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		if w.Code == 200 || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("invalid read", w.Code, w.Body.String())
		}
	}
	policy := operatorRoutePolicies["GET /v1/operator/disk-ops/status/{machine_id}"]
	if policy.Permission != operatorauth.View || policy.ServiceTokenEligible != serviceIneligible {
		t.Fatal("unsafe status eligibility", policy)
	}
}

func TestDiskScriptAndScheduleJSONFreshGateBeforeDecodeAndReplay(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	h.operatorRoutes(f.mux)
	for _, path := range []string{"/v1/operator/script-runs", "/v1/operator/schedules/upsert/apply", "/v1/operator/schedules/set-enabled/apply", "/v1/operator/schedules/fixture/run-now"} {
		assertDiskJSONLocalDenied(t, f.mux, path, "retry-key", `invalid JSON`)
	}
}
