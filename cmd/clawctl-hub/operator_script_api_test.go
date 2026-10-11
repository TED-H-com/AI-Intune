package main

import (
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestOperatorScriptAPI(t *testing.T) {
	f := observedOperatorFixture(t)
	enabled := true
	if err := f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, JobsEnabled: &enabled, ScriptV1: true}, jobsTestNow); err != nil {
		t.Fatal(err)
	}
	e, _ := scriptcatalog.Lookup("fleet-probe-v1")
	body := store.ScriptRunRequest{ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Reason: "probe facts"}
	raw, _ := json.Marshal(body)
	preview := diagnosticOperatorRequest(t, f.mux, "/v1/operator/script-runs/preview", "", string(raw))
	if preview.Code != 200 {
		t.Fatalf("preview %d %s", preview.Code, preview.Body.String())
	}
	var out store.ScriptRunResult
	if err := json.Unmarshal(preview.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	body.PreviewDigest = out.PreviewDigest
	raw, _ = json.Marshal(body)
	applied := diagnosticOperatorRequest(t, f.mux, "/v1/operator/script-runs", "probe-api-key", string(raw))
	if applied.Code != 201 {
		t.Fatalf("apply %d %s", applied.Code, applied.Body.String())
	}
	for _, change := range []func(*store.ScriptRunRequest){func(r *store.ScriptRunRequest) { r.ScriptID = "unknown" }, func(r *store.ScriptRunRequest) { r.ScriptSHA256 = strings.Repeat("b", 64) }, func(r *store.ScriptRunRequest) { r.Targets = make([]string, 51) }} {
		r := body
		change(&r)
		raw, _ := json.Marshal(r)
		rec := diagnosticOperatorRequest(t, f.mux, "/v1/operator/script-runs/preview", "", string(raw))
		if rec.Code != 400 {
			t.Fatalf("rejected request %d", rec.Code)
		}
	}
}
func TestScriptScopeDefenseInDepth(t *testing.T) {
	f := observedOperatorFixture(t)
	e, _ := scriptcatalog.Lookup("fleet-probe-v1")
	raw, _ := json.Marshal(store.ScriptRunRequest{ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Reason: "probe facts"})
	req := httptest.NewRequest(http.MethodPost, "/v1/operator/script-runs/preview", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req = verifiedOperatorRequest(req, operatorauth.View)
	rec := httptest.NewRecorder()
	(&hub{store: f.store}).handleScriptPreview(rec, req)
	if rec.Code < 400 {
		t.Fatal("view principal created script preview")
	}
}

func TestScriptPermissionInspectionReplaysBody(t *testing.T) {
	for _, body := range []string{`{"script_id":"fleet-probe-v1","args":{}}`, `{"script_id":"unknown"}`, strings.Repeat(" ", 17000)} {
		r := httptest.NewRequest(http.MethodPost, "/v1/operator/script-runs", strings.NewReader(body))
		permission := scriptRequestPermission(r)
		if len(body) < 16000 && permission != operatorauth.Operate {
			t.Fatal("read catalog requires operate")
		}
		replay, err := io.ReadAll(r.Body)
		if err != nil || string(replay) != body {
			t.Fatal("permission inspection changed body")
		}
	}
}

func TestScriptCatalogAPIObjectEnvelope(t *testing.T) {
	rec := httptest.NewRecorder()
	(&hub{}).handleScriptCatalog(rec, httptest.NewRequest(http.MethodGet, "/v1/operator/script-catalog", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("catalog status=%d headers=%v", rec.Code, rec.Header())
	}
	var response scriptcatalog.CatalogResponse
	decoder := json.NewDecoder(rec.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Items) != 1 || response.Items[0].ID != "fleet-probe-v1" {
		t.Fatalf("catalog %+v", response)
	}
}

func TestScriptRunRateLimitedBeforeAuditingAndSharedAcrossActions(t *testing.T) {
	f := observedOperatorFixture(t)
	enabled := true
	if err := f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, JobsEnabled: &enabled, ScriptV1: true}, jobsTestNow); err != nil {
		t.Fatal(err)
	}
	h := &hub{store: f.store}
	e, _ := scriptcatalog.Lookup("fleet-probe-v1")
	body := store.ScriptRunRequest{ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Reason: "probe facts"}
	call := func(apply bool, principal operatorauth.Principal, raw string) *httptest.ResponseRecorder {
		t.Helper()
		path := "/v1/operator/script-runs/preview"
		if apply {
			path = "/v1/operator/script-runs"
		}
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(raw))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "rate-test-key")
		// Headers and source/device changes cannot partition the stable subject bucket.
		r.Header.Set("X-Forwarded-For", "192.0.2.123")
		r.Header.Set("Forwarded", "for=192.0.2.123")
		r.Header.Set("X-Authenticated-Subject", "spoofed-subject")
		r = operatorauth.WithPrincipal(r, principal)
		rec := httptest.NewRecorder()
		h.handleScriptRun(rec, r, apply)
		return rec
	}
	base := httptest.NewRequest(http.MethodPost, "/v1/operator/script-runs/preview", nil)
	p, _ := operatorauth.PrincipalFromContext(verifiedOperatorRequest(base, operatorauth.Operate).Context())
	raw, _ := json.Marshal(body)
	preview := call(false, p, string(raw))
	if preview.Code != 200 {
		t.Fatalf("legitimate preview %d %s", preview.Code, preview.Body.String())
	}
	var result store.ScriptRunResult
	if err := json.Unmarshal(preview.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	body.PreviewDigest = result.PreviewDigest
	raw, _ = json.Marshal(body)
	for _, want := range []int{201, 200} {
		rec := call(true, p, string(raw))
		if rec.Code != want {
			t.Fatalf("legitimate apply/replay %d %s", rec.Code, rec.Body.String())
		}
	}
	// Freeze refill ahead of the real handler clock, then exhaust its same bucket.
	now := time.Now().Add(time.Hour)
	for i := 0; i < scriptRunSubjectBurst; i++ {
		if !h.scriptRunLimiter.allow(p.StableSubject(), now) {
			t.Fatal("failed to exhaust subject")
		}
	}
	before, err := f.store.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	p.NodeStableID = "other-node"
	p.SourceAddr = "192.0.2.124"
	for _, apply := range []bool{false, true} {
		rec := call(apply, p, `not JSON`)
		var apiError model.APIError
		if rec.Code != 429 || json.Unmarshal(rec.Body.Bytes(), &apiError) != nil || apiError.Code != "RATE_LIMITED" || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Retry-After") == "" {
			t.Fatalf("rate response %d %s", rec.Code, rec.Body.String())
		}
	}
	after, err := f.store.Audit("", 100)
	if err != nil || len(before) != len(after) {
		t.Fatalf("rate rejection wrote audit rows: before=%d after=%d err=%v", len(before), len(after), err)
	}
	// An independent authenticated subject still gets ordinary validation.
	p.TailnetUserID = "another-subject"
	if rec := call(false, p, `not JSON`); rec.Code != 400 {
		t.Fatalf("independent principal was blocked: %d", rec.Code)
	}
}

func TestScriptRunGlobalLimitAndMissingPrincipal(t *testing.T) {
	h := &hub{}
	now := time.Now().Add(time.Hour)
	for i := 0; i < scriptRunGlobalBurst; i++ {
		if !h.scriptRunLimiter.allow(fmt.Sprintf("tailscale-user:%d", i), now) {
			t.Fatal("failed to exhaust global limit")
		}
	}
	for _, apply := range []bool{false, true} {
		r := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, "/v1/operator/script-runs", strings.NewReader(`not JSON`)), operatorauth.Operate)
		rec := httptest.NewRecorder()
		h.handleScriptRun(rec, r, apply)
		var response model.APIError
		if rec.Code != 429 || json.Unmarshal(rec.Body.Bytes(), &response) != nil || response.Code != "RATE_LIMITED" {
			t.Fatalf("global response %d %s", rec.Code, rec.Body.String())
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/operator/script-runs", nil)
	r.Header.Set("X-Authenticated-Subject", "forged")
	r.Header.Set("X-Forwarded-For", "192.0.2.123")
	rec := httptest.NewRecorder()
	h.handleScriptRun(rec, r, false)
	if rec.Code != 403 {
		t.Fatalf("missing principal response %d", rec.Code)
	}
}
