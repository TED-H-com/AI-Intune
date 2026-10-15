package main

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestOperatorAdminScopeCentralAuthorization(t *testing.T) {
	st := boundaryStore(t)
	actor, err := st.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	var allowed []string
	for route, policy := range operatorRoutePolicies {
		if policy.ServiceTokenEligible == serviceEligibleOperatorAdmin {
			allowed = append(allowed, route)
		}
	}
	if len(allowed) != 14 {
		t.Fatalf("operator-admin routes=%d", len(allowed))
	}
	forbidden := []string{
		"DELETE /v1/operator/machines/{id}", "DELETE /v1/operator/tenants/{id}",
		"POST /account/security/totp/begin", "POST /account/security/totp/confirm", "POST /account/security/totp/disable", "POST /account/security/password", "POST /account/security/recovery-codes/regenerate",
		"POST /account/service-tokens/create", "POST /v1/operator/service-tokens/rotate",
		"POST /account/users/create", "POST /account/users/disable", "POST /account/users/enable", "POST /account/users/email", "POST /account/users/rename",
	}
	for _, scope := range []string{"view", "operate", "operator-admin"} {
		routes := []string{"GET /v1/operator/jobs"}
		if scope == "operator-admin" {
			routes = allowed
		}
		_, secret, err := st.CreateServiceToken(store.ServiceToken{Name: "bot-" + scope, Scope: scope, ExpiresAt: time.Now().Add(time.Hour), Allowlist: routes}, actor.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range append(append([]string{}, allowed...), forbidden...) {
			t.Run(scope+"/"+route, func(t *testing.T) {
				policy, exists := operatorRoutePolicies[route]
				if !exists {
					policy = operatorRoutePolicy{operatorauth.Admin, operatorJSON, operator.SourceKindOperatorAPI, operatorSecurityLocked, serviceIneligible}
				}
				inner := http.NewServeMux()
				reached := false
				inner.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) { reached = true; w.WriteHeader(204) })
				b := newOperatorBoundary(inner, nil, st, map[string]operatorRoutePolicy{route: policy}, testOperatorAuthority)
				method, path, _ := strings.Cut(route, " ")
				path = strings.ReplaceAll(path, "{id}", "sample")
				path = strings.ReplaceAll(path, "{operation}", "upsert")
				path = strings.ReplaceAll(path, "{phase}", "preview")
				req := newBoundaryRequest(method, path, strings.NewReader("{}"))
				req.Header.Set("Authorization", "Bearer "+secret)
				req.Header.Set("Content-Type", "application/json")
				rec := httptest.NewRecorder()
				b.ServeHTTP(rec, req)
				wantAllowed := operatorauth.OperatorAdminRoute(route) && scope == "operator-admin"
				if reached != wantAllowed {
					t.Fatalf("handler reached=%t status=%d body=%s", reached, rec.Code, rec.Body.String())
				}
				if wantAllowed && rec.Code != 204 {
					t.Fatal(rec.Code)
				}
				if !wantAllowed {
					code := "SERVICE_TOKEN_SCOPE_REQUIRED"
					if operatorauth.DangerousAction(route) != "" {
						code = "SERVICE_TOKEN_ACTION_FORBIDDEN"
					}
					if rec.Code != 403 || !strings.Contains(rec.Body.String(), code) {
						t.Fatalf("denial=%d %s", rec.Code, rec.Body.String())
					}
				}
			})
		}
	}
}

func TestOperatorAdminScheduleAPI(t *testing.T) {
	f := observedOperatorFixture(t)
	actor, err := f.store.CreateFirstAdmin("admin", usersPassword)
	if err != nil {
		t.Fatal(err)
	}
	routes := []string{"POST /v1/operator/schedules/{operation}/{phase}", "POST /v1/operator/schedules/{id}/run-now"}
	_, secret, err := f.store.CreateServiceToken(store.ServiceToken{Name: "scheduler", Scope: "operator-admin", ExpiresAt: time.Now().Add(time.Hour), Allowlist: routes}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if err = f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, JobsEnabled: &enabled, ScriptV1: true}, jobsTestNow); err != nil {
		t.Fatal(err)
	}
	b := newOperatorBoundary(f.mux, nil, f.store, operatorRoutePolicies, testOperatorAuthority)
	call := func(path string, body any, key string) *httptest.ResponseRecorder {
		raw, _ := json.Marshal(body)
		req := newBoundaryRequest("POST", path, strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+secret)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Idempotency-Key", key)
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		return rec
	}
	entry, _ := scriptcatalog.Lookup("fleet-probe-v1")
	req := store.ScheduleRequest{Name: "bot-probe", ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Cron: "*/5 * * * *", Reason: "routine inventory", Enabled: true}
	mutate := func(op, key string) store.Schedule {
		preview := call("/v1/operator/schedules/"+op+"/preview", req, "")
		if preview.Code != 200 {
			t.Fatalf("preview %d %s", preview.Code, preview.Body.String())
		}
		var result store.ScheduleResult
		if err := json.Unmarshal(preview.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		req.PreviewDigest = result.PreviewDigest
		applied := call("/v1/operator/schedules/"+op+"/apply", req, key)
		if applied.Code != 200 && applied.Code != 201 {
			t.Fatalf("apply %d %s", applied.Code, applied.Body.String())
		}
		if err := json.Unmarshal(applied.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Schedule
	}
	v := mutate("upsert", "create")
	req.ID = v.ID
	req.ExpectedRevision = v.Revision
	req.Cron = "*/10 * * * *"
	req.PreviewDigest = ""
	v = mutate("upsert", "edit")
	req = store.ScheduleRequest{ID: v.ID, ExpectedRevision: v.Revision, Enabled: false, Reason: "pause inventory"}
	v = mutate("set-enabled", "disable")
	req = store.ScheduleRequest{ID: v.ID, ExpectedRevision: v.Revision, Enabled: true, Reason: "resume inventory"}
	v = mutate("set-enabled", "enable")
	run := call("/v1/operator/schedules/"+v.ID+"/run-now", struct{}{}, "run")
	if run.Code != 200 {
		t.Fatalf("run %d %s", run.Code, run.Body.String())
	}
}
