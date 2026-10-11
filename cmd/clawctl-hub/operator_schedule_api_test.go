package main

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOperatorScheduleAPI(t *testing.T) {
	f := observedOperatorFixture(t)
	enabled := true
	if e := f.store.RecordCheckin(f.machine.id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: jobsTestNow, JobsEnabled: &enabled, ScriptV1: true}, jobsTestNow); e != nil {
		t.Fatal(e)
	}
	entry, _ := scriptcatalog.Lookup("fleet-probe-v1")
	r := store.ScheduleRequest{Name: "probe-check", ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Cron: "*/5 * * * *", Enabled: true, Reason: "probe facts"}
	raw, _ := json.Marshal(r)
	rec := diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/upsert/preview", "", string(raw))
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var result store.ScheduleResult
	if e := json.Unmarshal(rec.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	r.PreviewDigest = result.PreviewDigest
	raw, _ = json.Marshal(r)
	rec = diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/upsert/apply", "schedule-api", string(raw))
	if rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if e := json.Unmarshal(rec.Body.Bytes(), &result); e != nil {
		t.Fatal(e)
	}
	for _, path := range []string{"/v1/operator/schedules", "/v1/operator/schedules/" + result.Schedule.ID} {
		req := verifiedOperatorRequest(httptest.NewRequest(http.MethodGet, path, nil), operatorauth.View)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, req)
		if w.Code != 200 {
			t.Fatalf("read %d %s", w.Code, w.Body.String())
		}
	}
	req := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, "/v1/operator/schedules/upsert/preview", strings.NewReader(string(raw))), operatorauth.View)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("view %d", w.Code)
	}
	rec = diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/"+result.Schedule.ID+"/run-now", "", `{}`)
	if rec.Code != 200 {
		t.Fatalf("run-now %d %s", rec.Code, rec.Body.String())
	}
}
