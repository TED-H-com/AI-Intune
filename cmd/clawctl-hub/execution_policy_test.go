package main

import (
	"github.com/teddashh/AI-Intune/internal/expect"
	"net/http"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestMonitorOnlyHubRefusesExecutionKeepsIdentityAndCheckin(t *testing.T) {
	f := newJobsFixture(t, "protected-hub-machine")
	f.store.SetExpectations(&expect.Set{Configured: true})
	if err := f.store.PublishExpectationsPolicy(time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	checkin := model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, ExecutionPolicyV1: true, MonitorOnlySupported: true}
	if err := f.store.RecordCheckin(f.machine.id, checkin, jobsTestNow); err != nil {
		t.Fatal(err)
	}
	req := store.ExecutionPolicyRequest{MachineID: f.machine.id, Mode: model.ExecutionMonitorOnly, Reason: "protect appliance", ExpectedRevision: 1, Audit: store.AuditEntry{AuthSubject: "local-user:admin", AuthMethod: operatorauth.AuthMethodLocalAPI, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)}}
	preview, err := f.store.ManageExecutionPolicy(req, false)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	req.IdempotencyKey = "hub-profile"
	if _, err = f.store.ManageExecutionPolicy(req, true); err != nil {
		t.Fatal(err)
	}
	for _, surface := range []struct{ method, path string }{
		{"GET", "/v1/jobs/next"}, {"POST", "/v1/jobs/job-one/claims"}, {"POST", "/v1/jobs/job-one/events"}, {"POST", "/v1/jobs/job-one/verifications"}, {"GET", "/v1/agent/terminal-link"}, {"GET", "/v1/ops-manifests/manifest-one"},
	} {
		result := requestJobAPI(t, f.mux, surface.method, surface.path, f.machine.token, nil)
		if result.Code != http.StatusForbidden {
			t.Fatalf("%s %s status=%d", surface.method, surface.path, result.Code)
		}
	}
	checkin.SentAt = jobsTestNow.Add(time.Second)
	response := requestJobAPI(t, f.mux, "POST", "/v1/checkins", f.machine.token, checkin)
	if response.Code != 200 {
		t.Fatalf("checkin status=%d %s", response.Code, response.Body.String())
	}
	for _, path := range []string{"/v1/agent/readiness"} {
		response = requestJobAPI(t, f.mux, "GET", path, f.machine.token, nil)
		if response.Code != 200 {
			t.Fatalf("%s=%d", path, response.Code)
		}
	}
}
