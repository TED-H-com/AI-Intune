package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestServiceTokenReadScriptsBoundary(t *testing.T) {
	f := observedOperatorFixture(t)
	enabled := true
	if err := f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, JobsEnabled: &enabled, ScriptV1: true}, jobsTestNow); err != nil {
		t.Fatal(err)
	}
	admin, err := f.store.CreateFirstAdmin("script-admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	routes := []string{"POST /v1/operator/script-runs/preview", "POST /v1/operator/script-runs", "POST /v1/operator/schedules/{operation}/{phase}", "POST /v1/operator/schedules/{id}/run-now"}
	_, secret, err := f.store.CreateServiceToken(store.ServiceToken{Name: "hermes", Scope: "operate", ExpiresAt: time.Now().Add(time.Hour), Allowlist: routes}, admin.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	b := newOperatorBoundary(f.mux, &boundaryAuthorizer{}, f.store, operatorRoutePolicies, testOperatorAuthority)
	call := func(path string, body store.ScriptRunRequest) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		r := newBoundaryRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		r.Header.Set("Authorization", "Bearer "+secret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "service-script-key")
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	e, _ := scriptcatalog.Lookup("fleet-probe-v1")
	body := store.ScriptRunRequest{ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Reason: "collect facts"}
	preview := call("/v1/operator/script-runs/preview", body)
	if preview.Code != 200 {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	var out store.ScriptRunResult
	if err := json.Unmarshal(preview.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	body.PreviewDigest = out.PreviewDigest
	applied := call("/v1/operator/script-runs", body)
	if applied.Code != 201 {
		t.Fatalf("apply: %d %s", applied.Code, applied.Body.String())
	}
	// Even an already consumed digest/key cannot bypass classification on apply.
	for _, id := range []string{"bat-sweep-report-v1", "unknown"} {
		rejected := body
		rejected.ScriptID = id
		for _, path := range []string{"/v1/operator/script-runs/preview", "/v1/operator/script-runs"} {
			w := call(path, rejected)
			if w.Code != 403 || !strings.Contains(w.Body.String(), "SERVICE_TOKEN_READ_SCRIPTS_ONLY") {
				t.Fatalf("%s %s: %d %s", id, path, w.Code, w.Body.String())
			}
		}
	}
	for _, path := range []string{"/v1/operator/schedules/upsert/preview", "/v1/operator/schedules/upsert/apply", "/v1/operator/schedules/set-enabled/preview", "/v1/operator/schedules/set-enabled/apply", "/v1/operator/schedules/s-1/run-now"} {
		if w := call(path, body); w.Code != 401 {
			t.Fatalf("schedule %s: %d", path, w.Code)
		}
	}
	var count int
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes' AND auth_method='service-token' AND action IN (?,?) AND outcome='ok'`, store.AuditScriptPreview, store.AuditScriptApply).Scan(&count); err != nil || count != 2 {
		t.Fatalf("success audits=%d err=%v", count, err)
	}
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes' AND action IN (?,?) AND outcome!='ok'`, store.AuditScriptPreview, store.AuditScriptApply).Scan(&count); err != nil || count != 4 {
		t.Fatalf("denial audits=%d err=%v", count, err)
	}
	// Legacy view allowlists cannot acquire operate permission.
	_, viewSecret, err := f.store.CreateServiceToken(store.ServiceToken{Name: "viewer", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"GET /v1/operator/machines"}}, admin.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	secret = viewSecret
	b = newOperatorBoundary(f.mux, &boundaryAuthorizer{}, f.store, operatorRoutePolicies, testOperatorAuthority)
	if w := call("/v1/operator/script-runs/preview", body); w.Code != 401 {
		t.Fatalf("view token status=%d", w.Code)
	}
	for _, route := range routes[:2] {
		if _, _, err := f.store.CreateServiceToken(store.ServiceToken{Name: "invalid-viewer", Scope: "view", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{route}}, admin.AccountID); err == nil {
			t.Fatal("view script allowlist accepted")
		}
	}
}

func TestServiceTokenScriptHandlerScopeAndRateLimit(t *testing.T) {
	f := observedOperatorFixture(t)
	h := &hub{store: f.store}
	p := operatorauth.Principal{AuthMethod: operatorauth.AuthMethodServiceToken, TailnetUserID: "hermes", GrantedCapabilities: operatorauth.CapabilityNames{View: "view"}}
	r := httptest.NewRequest("POST", "/v1/operator/script-runs/preview", strings.NewReader(`{"script_id":"fleet-probe-v1"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.handleScriptPreview(w, operatorauth.WithPrincipal(r, p))
	if w.Code != 403 {
		t.Fatalf("view handler status=%d", w.Code)
	}
	now := time.Now().Add(time.Hour)
	for i := 0; i < scriptRunSubjectBurst; i++ {
		h.scriptRunLimiter.allow(p.StableSubject(), now)
	}
	for _, apply := range []bool{false, true} {
		w = httptest.NewRecorder()
		h.handleScriptRun(w, operatorauth.WithPrincipal(r, p), apply)
		if w.Code != 429 {
			t.Fatalf("token rate limit=%d", w.Code)
		}
	}
}

// A valid human admin preview for the real write-equivalent BAT catalog entry
// must not authorize a service token's apply.
func TestServiceTokenBATCatalogPreviewAndApplyDenied(t *testing.T) {
	f := observedOperatorFixture(t)
	enabled := true
	if err := f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, JobsEnabled: &enabled, ScriptV1: true}, jobsTestNow); err != nil {
		t.Fatal(err)
	}
	entry, exists := scriptcatalog.Lookup("bat-sweep-report-v1")
	if !exists || entry.Mode != "write" {
		t.Fatal("real BAT catalog entry must be write-class")
	}
	body := store.ScriptRunRequest{ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: json.RawMessage(`{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `"}`), Targets: []string{f.machine.id}, TimeoutSeconds: 600, Reason: "BAT report pilot"}
	raw, _ := json.Marshal(body)
	human := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, "/v1/operator/script-runs/preview", strings.NewReader(string(raw))), operatorauth.Admin)
	human.Header.Set("Content-Type", "application/json")
	p, _ := operatorauth.PrincipalFromContext(human.Context())
	p.GrantedCapabilities.Admin = testOperatorCapability(operatorauth.Admin)
	preview := httptest.NewRecorder()
	f.mux.ServeHTTP(preview, operatorauth.WithPrincipal(human, p))
	if preview.Code != 200 {
		t.Fatalf("human preview: %d %s", preview.Code, preview.Body.String())
	}
	var result store.ScriptRunResult
	if err := json.Unmarshal(preview.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	body.PreviewDigest = result.PreviewDigest
	admin, err := f.store.CreateFirstAdmin("script-admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	_, secret, err := f.store.CreateServiceToken(store.ServiceToken{Name: "hermes-bat", Scope: "operate", ExpiresAt: time.Now().Add(time.Hour), Allowlist: []string{"POST /v1/operator/script-runs/preview", "POST /v1/operator/script-runs"}}, admin.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	boundary := newOperatorBoundary(f.mux, &boundaryAuthorizer{}, f.store, operatorRoutePolicies, testOperatorAuthority)
	for _, path := range []string{"/v1/operator/script-runs/preview", "/v1/operator/script-runs"} {
		raw, _ = json.Marshal(body)
		request := newBoundaryRequest(http.MethodPost, path, strings.NewReader(string(raw)))
		request.Header.Set("Authorization", "Bearer "+secret)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "service-bat-denied")
		response := httptest.NewRecorder()
		boundary.ServeHTTP(response, request)
		var apiError model.APIError
		if response.Code != http.StatusForbidden || json.Unmarshal(response.Body.Bytes(), &apiError) != nil || apiError.Code != "SERVICE_TOKEN_READ_SCRIPTS_ONLY" {
			t.Fatalf("%s: %d %s", path, response.Code, response.Body.String())
		}
	}
	var count int
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes-bat' AND auth_method='service-token' AND action IN (?,?) AND outcome!='ok'`, store.AuditScriptPreview, store.AuditScriptApply).Scan(&count); err != nil || count != 2 {
		t.Fatalf("BAT denial audits=%d err=%v", count, err)
	}
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("BAT jobs=%d err=%v", count, err)
	}
}
