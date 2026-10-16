package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
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
	routes := []string{"POST /v1/operator/script-runs/preview", "POST /v1/operator/script-runs"}
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
		if w := call(path, body); w.Code != 403 {
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

func TestServiceTokenScriptEvidenceOnly(t *testing.T) {
	f := observedOperatorFixture(t)
	now := time.Now().UTC()
	enabled := true
	if err := f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: now, JobsEnabled: &enabled, ScriptV1: true}, now); err != nil {
		t.Fatal(err)
	}
	actor, err := f.store.CreateFirstAdmin("evidence-admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	route := "GET /v1/operator/jobs/{id}/evidence"
	_, secret, err := f.store.CreateServiceToken(store.ServiceToken{Name: "hermes-evidence", Scope: "view", ExpiresAt: now.Add(time.Hour), Allowlist: []string{route}}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	boundary := newOperatorBoundary(f.mux, &boundaryAuthorizer{}, f.store, operatorRoutePolicies, testOperatorAuthority)
	createScript := func(id string, args json.RawMessage) string {
		t.Helper()
		entry, exists := scriptcatalog.Lookup(id)
		if !exists {
			t.Fatal("missing catalog entry")
		}
		req := store.ScriptRunRequest{ScriptID: id, ScriptSHA256: entry.SHA256, Args: args, Targets: []string{f.machine.id}, Reason: "evidence test"}
		audit := store.AuditEntry{AuthSubject: "local-user:" + actor.AccountID, AuthMethod: operatorauth.AuthMethodLocalAccountSession, AuthCapability: "admin"}
		if entry.Mode == "read" {
			audit.AuthCapability = "operate"
		}
		preview, err := f.store.ScriptRun(req, false, "", audit)
		if err != nil {
			t.Fatal(err)
		}
		req.PreviewDigest = preview.PreviewDigest
		result, err := f.store.ScriptRun(req, true, "evidence-"+id, audit)
		if err != nil {
			t.Fatal(err)
		}
		job, err := f.store.Job(result.JobIDs[0])
		if err != nil {
			t.Fatal(err)
		}
		desired, err := f.store.DesiredState(job.DesiredID)
		if err != nil {
			t.Fatal(err)
		}
		spec, err := scriptcatalog.Decode([]byte(desired.Spec))
		if err != nil || spec.ExecutionMode != entry.Mode {
			t.Fatal("execution-time mode not persisted")
		}
		return result.JobIDs[0]
	}
	readID := createScript("fleet-probe-v1", json.RawMessage(`{}`))
	// Existing agents strictly reject unknown fields. Exercise actual job
	// delivery with the pre-mode decoder shape and verify its payload digest.
	next := requestJobAPI(t, f.mux, http.MethodGet, "/v1/jobs/next", f.machine.token, nil)
	if next.Code != http.StatusOK {
		t.Fatalf("next job status=%d", next.Code)
	}
	var wire model.JobResponse
	if err := json.Unmarshal(next.Body.Bytes(), &wire); err != nil {
		t.Fatal(err)
	}
	var legacySpec struct {
		Kind         string          `json:"kind"`
		ScriptID     string          `json:"script_id"`
		ScriptSHA256 string          `json:"script_sha256"`
		Args         json.RawMessage `json:"args"`
	}
	decoder := json.NewDecoder(bytes.NewReader(wire.Spec))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&legacySpec); err != nil {
		t.Fatalf("legacy agent decoder: %v", err)
	}
	if wire.JobID != readID || legacySpec.ScriptID != "fleet-probe-v1" || wire.ArtifactDigest != "sha256:"+scriptcatalog.Digest(wire.Spec) {
		t.Fatal("agent projection identity/digest mismatch")
	}
	storedJob, err := f.store.Job(readID)
	if err != nil {
		t.Fatal(err)
	}
	storedSpec, err := f.store.DesiredState(storedJob.DesiredID)
	if err != nil {
		t.Fatal(err)
	}
	decodedStored, err := scriptcatalog.Decode([]byte(storedSpec.Spec))
	if err != nil || decodedStored.ExecutionMode != "read" || storedJob.ArtifactDigest != "sha256:"+scriptcatalog.Digest([]byte(storedSpec.Spec)) {
		t.Fatal("agent delivery changed persisted approval metadata/digest")
	}

	lease, err := f.store.ClaimJob(readID, f.machine.id, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AdvanceJobByAgent(readID, f.machine.id, lease, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordVerification(readID, f.machine.id, lease, scriptcatalog.Kind, "fleet-probe-v1", 0, "read-script-results", "", true, now); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal(scriptcatalog.Result{StdoutSHA256: scriptcatalog.Digest([]byte("read-script-results")), StderrSHA256: scriptcatalog.Digest(nil), ExitCode: 0})
	if err != nil {
		t.Fatal(err)
	}
	if err := f.store.RecordVerification(readID, f.machine.id, lease, "script_v1_metadata", string(metadata), 0, "", "", true, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.AdvanceJobByAgent(readID, f.machine.id, lease, deploy.FinishWork, now); err != nil {
		t.Fatal(err)
	}
	if state, err := f.store.MarkSucceededIfVerified(readID, now); err != nil || state != deploy.Succeeded {
		t.Fatalf("complete script: %s %v", state, err)
	}

	writeID := createScript("bat-sweep-report-v1", json.RawMessage(`{"hosts":["sample-host"],"connector_tree_sha256":"`+strings.Repeat("a", 64)+`"}`))
	// Create a real write job first, then simulate a same-hash catalog-only
	// reclassification at the shared authorization predicate.
	writeJob, err := f.store.Job(writeID)
	if err != nil {
		t.Fatal(err)
	}
	writeDesired, err := f.store.DesiredState(writeJob.DesiredID)
	if err != nil {
		t.Fatal(err)
	}
	writeSpec, err := scriptcatalog.Decode([]byte(writeDesired.Spec))
	if err != nil {
		t.Fatal(err)
	}
	reclassified, exists := scriptcatalog.Lookup(writeSpec.ScriptID)
	if !exists || writeSpec.ExecutionMode != "write" {
		t.Fatal("expected real historical write job")
	}
	reclassified.Mode = "read"
	if serviceTokenScriptEvidenceAllowed(writeSpec, reclassified, writeDesired.ResourceID) {
		t.Fatal("catalog reclassification exposed historical write job")
	}
	otherID := createOperatorReadJob(t, f.store, f.machine.id, "cnode-operator", "NON_SCRIPT_EVIDENCE")
	for _, tc := range []struct {
		name, id string
		status   int
	}{
		{"read script", readID, http.StatusOK},
		{"write script", writeID, http.StatusForbidden},
		{"non-script job", otherID, http.StatusForbidden},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := "/v1/operator/jobs/" + tc.id + "/evidence"
			request := newBoundaryRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer "+secret)
			response := httptest.NewRecorder()
			boundary.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("status=%d", response.Code)
			}
			if tc.status == http.StatusForbidden {
				assertAPIError(t, response, http.StatusForbidden, "SERVICE_TOKEN_SCRIPT_EVIDENCE_ONLY")
				if strings.Contains(response.Body.String(), "NON_SCRIPT_EVIDENCE") {
					t.Fatal("denial exposed evidence")
				}
			} else if !strings.Contains(response.Body.String(), "read-script-results") {
				t.Fatal("missing script output")
			}
			// A local human session retains normal view access to every job kind.
			human := httptest.NewRequest(http.MethodGet, path, nil)
			principal := operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, GrantedCapabilities: operatorauth.CapabilityNames{View: "view"}}
			humanResponse := httptest.NewRecorder()
			f.mux.ServeHTTP(humanResponse, operatorauth.WithPrincipal(human, principal))
			if humanResponse.Code != http.StatusOK {
				t.Fatalf("human status=%d", humanResponse.Code)
			}
		})
	}
	var denials int
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes-evidence' AND auth_method='service-token' AND action=? AND subject=? AND outcome!='ok'`, store.AuditOperatorDenied, route).Scan(&denials); err != nil || denials != 2 {
		t.Fatalf("denial audits=%d err=%v", denials, err)
	}
	job, err := f.store.Job(readID)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := f.store.DesiredState(job.DesiredID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, mode string }{
		{"legacy mode absent", ""},
		// The current catalog is read with the same ID/hash. The historical
		// spec below records write, exactly the state after reclassification.
		{"historical write reclassified read with same hash", "write"},
		{"unknown execution mode", "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := scriptcatalog.Decode([]byte(desired.Spec))
			if err != nil {
				t.Fatal(err)
			}
			spec.ExecutionMode = tc.mode
			raw, err := json.Marshal(spec)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.store.DB().Exec(`UPDATE desired_state SET spec=? WHERE desired_id=?`, string(raw), job.DesiredID); err != nil {
				t.Fatal(err)
			}
			path := "/v1/operator/jobs/" + readID + "/evidence"
			request := newBoundaryRequest(http.MethodGet, path, nil)
			request.Header.Set("Authorization", "Bearer "+secret)
			response := httptest.NewRecorder()
			boundary.ServeHTTP(response, request)
			assertAPIError(t, response, http.StatusForbidden, "SERVICE_TOKEN_SCRIPT_EVIDENCE_ONLY")
			if strings.Contains(response.Body.String(), "read-script-results") {
				t.Fatal("historical evidence disclosed")
			}
			human := httptest.NewRequest(http.MethodGet, path, nil)
			principal := operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, GrantedCapabilities: operatorauth.CapabilityNames{View: "view"}}
			humanResponse := httptest.NewRecorder()
			f.mux.ServeHTTP(humanResponse, operatorauth.WithPrincipal(human, principal))
			if humanResponse.Code != http.StatusOK {
				t.Fatalf("human status=%d", humanResponse.Code)
			}
		})
	}
	if err := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes-evidence' AND auth_method='service-token' AND action=? AND subject=? AND outcome!='ok'`, store.AuditOperatorDenied, route).Scan(&denials); err != nil || denials != 5 {
		t.Fatalf("historical denial audits=%d err=%v", denials, err)
	}

}

func TestScriptEvidenceEligibilityCannotBeAssignedToOtherRoutes(t *testing.T) {
	policy := operatorRoutePolicies["GET /v1/operator/jobs/{id}/evidence"]
	if policy.ServiceTokenEligible != serviceEligibleScriptEvidenceOnly || !operatorPolicyAdmissible("GET /v1/operator/jobs/{id}/evidence", policy) {
		t.Fatal("missing narrow evidence eligibility")
	}
	if operatorPolicyAdmissible("GET /v1/operator/machines/{id}/evidence", policy) {
		t.Fatal("script evidence class allowed on another route")
	}
	policy.Permission = operatorauth.Operate
	if operatorPolicyAdmissible("GET /v1/operator/jobs/{id}/evidence", policy) {
		t.Fatal("script evidence class must remain view")
	}
	found := false
	for _, route := range hermesServiceRoutes {
		if route == "GET /v1/operator/jobs/{id}/evidence" {
			found = true
		}
	}
	if !found {
		t.Fatal("Hermes preset missing script evidence")
	}
}

func TestServiceTokenDiskV2EvidenceIsHumanOnly(t *testing.T) {
	for _, id := range []string{"disk-safe-preview-v2", "disk-safe-clean-v2", "disk-deep-report-v1"} {
		entry, ok := scriptcatalog.Lookup(id)
		if !ok {
			t.Fatal(id)
		}
		spec := scriptcatalog.Spec{ScriptID: id, ScriptSHA256: entry.SHA256, ExecutionMode: entry.Mode, Policy: json.RawMessage(`{"protect_paths":["/private/fixture"]}`)}
		if serviceTokenScriptEvidenceAllowed(spec, entry, id) {
			t.Fatal("disk evidence exposed to service token", id)
		}
	}
}

func TestServiceTokenDiskPreviewEvidenceRouteRejectsPinnedPaths(t *testing.T) {
	f := observedOperatorFixture(t)
	now := time.Now().UTC()
	account, err := f.store.CreateFirstAdmin("disk-evidence-admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	route := "GET /v1/operator/jobs/{id}/evidence"
	_, secret, err := f.store.CreateServiceToken(store.ServiceToken{Name: "disk-evidence", Scope: "view", ExpiresAt: now.Add(time.Hour), Allowlist: []string{route}}, account.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	entry, _ := scriptcatalog.Lookup("disk-safe-preview-v2")
	policy := store.DefaultDiskPolicy()
	policy.ProtectPaths = []string{"/private/fixture"}
	body, _ := json.Marshal(policy)
	_, _, digest, err := store.CanonicalDiskPolicy(body)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]string{"scope": "user", "policy_id": "fixture", "policy_digest": digest})
	spec, _ := json.Marshal(scriptcatalog.Spec{Kind: scriptcatalog.Kind, ScriptID: entry.ID, ScriptSHA256: entry.SHA256, ExecutionMode: "read", Args: args, Policy: body})
	jobID := f.newJob(t, "sha256:"+scriptcatalog.Digest(spec))
	job, err := f.store.Job(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = f.store.DB().Exec(`UPDATE desired_state SET resource_kind=?,resource_id=?,spec=? WHERE desired_id=?`, scriptcatalog.Kind, entry.ID, string(spec), job.DesiredID); err != nil {
		t.Fatal(err)
	}
	boundary := newOperatorBoundary(f.mux, &boundaryAuthorizer{}, f.store, operatorRoutePolicies, testOperatorAuthority)
	path := "/v1/operator/jobs/" + jobID + "/evidence"
	request := newBoundaryRequest(http.MethodGet, path, nil)
	request.Header.Set("Authorization", "Bearer "+secret)
	response := httptest.NewRecorder()
	boundary.ServeHTTP(response, request)
	assertAPIError(t, response, http.StatusForbidden, "SERVICE_TOKEN_SCRIPT_EVIDENCE_ONLY")
	if strings.Contains(response.Body.String(), "/private/fixture") || strings.Contains(response.Body.String(), "protect_paths") {
		t.Fatal("token denial leaked policy")
	}
	human := operatorauth.WithPrincipal(httptest.NewRequest(http.MethodGet, path, nil), operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, GrantedCapabilities: operatorauth.CapabilityNames{View: "view"}})
	response = httptest.NewRecorder()
	f.mux.ServeHTTP(response, human)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "/private/fixture") {
		t.Fatal("human evidence unavailable", response.Code)
	}
}
