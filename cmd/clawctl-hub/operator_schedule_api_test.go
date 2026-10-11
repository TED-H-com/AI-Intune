package main

import (
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	if result.Schedule.LastJobIDs == nil {
		t.Fatal("preview last_job_ids must be an array")
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
		if path == "/v1/operator/schedules" {
			var list store.ScheduleListResponse
			if e := json.Unmarshal(w.Body.Bytes(), &list); e != nil || len(list.Items) != 1 {
				t.Fatalf("list envelope %+v %v", list, e)
			}
		} else {
			var got store.Schedule
			if e := json.Unmarshal(w.Body.Bytes(), &got); e != nil || got.ID != result.Schedule.ID || got.LastJobIDs == nil {
				t.Fatalf("get shape %+v %v", got, e)
			}
		}
	}
	disable := store.ScheduleRequest{ID: result.Schedule.ID, ExpectedRevision: result.Schedule.Revision, Enabled: false, Reason: "pause schedule"}
	disableRaw, _ := json.Marshal(disable)
	rec = diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/set-enabled/preview", "", string(disableRaw))
	if rec.Code != 200 {
		t.Fatalf("enable preview %d %s", rec.Code, rec.Body.String())
	}
	var disabled store.ScheduleResult
	if e := json.Unmarshal(rec.Body.Bytes(), &disabled); e != nil || disabled.Schedule.LastJobIDs == nil {
		t.Fatalf("enable preview shape %+v %v", disabled, e)
	}
	disable.PreviewDigest = disabled.PreviewDigest
	disableRaw, _ = json.Marshal(disable)
	for _, status := range []int{201, 200} {
		rec = diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/set-enabled/apply", "schedule-disable-api", string(disableRaw))
		if rec.Code != status {
			t.Fatalf("enable apply %d %s", rec.Code, rec.Body.String())
		}
		if e := json.Unmarshal(rec.Body.Bytes(), &disabled); e != nil || disabled.Schedule.LastJobIDs == nil || disabled.Replayed != (status == 200) {
			t.Fatalf("enable apply shape %+v %v", disabled, e)
		}
	}
	req := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, "/v1/operator/schedules/upsert/preview", strings.NewReader(string(raw))), operatorauth.View)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, req)
	if w.Code != 403 {
		t.Fatalf("view %d", w.Code)
	}
	rec = diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/"+result.Schedule.ID+"/run-now", "manual-api", `{}`)
	if rec.Code != 200 {
		t.Fatalf("run-now %d %s", rec.Code, rec.Body.String())
	}
	var run store.ScheduleRunNowResponse
	if e := json.Unmarshal(rec.Body.Bytes(), &run); e != nil || len(run.JobIDs) != 1 {
		t.Fatalf("run shape %+v %v", run, e)
	}
	rec = diagnosticOperatorRequest(t, f.mux, "/v1/operator/schedules/"+result.Schedule.ID+"/run-now", "manual-api", `{}`)
	if rec.Code != 200 {
		t.Fatalf("duplicate run %d", rec.Code)
	}
	if e := json.Unmarshal(rec.Body.Bytes(), &run); e != nil || run.JobIDs == nil || len(run.JobIDs) != 1 || !run.Replayed {
		t.Fatalf("empty run shape %+v %v", run, e)
	}

}

func TestOperatorScheduleEmptyListEnvelope(t *testing.T) {
	f := observedOperatorFixture(t)
	w := httptest.NewRecorder()
	(&hub{store: f.store}).handleScheduleList(w, httptest.NewRequest(http.MethodGet, "/v1/operator/schedules", nil))
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	var out store.ScheduleListResponse
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || out.Items == nil || len(out.Items) != 0 {
		t.Fatalf("empty envelope %+v %v", out, e)
	}
}

func TestScheduleMutationsRateLimitBeforeAudit(t *testing.T) {
	for _, global := range []bool{false, true} {
		t.Run(fmt.Sprintf("global-%t", global), func(t *testing.T) {
			f := observedOperatorFixture(t)
			h := &hub{store: f.store}
			now := time.Now().Add(time.Hour)
			probe := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, "/v1/operator/schedules/upsert/preview", nil), operatorauth.Operate)
			p, _ := operatorauth.PrincipalFromContext(probe.Context())
			if global {
				for i := 0; i < scriptRunGlobalBurst; i++ {
					if !h.scriptRunLimiter.allow(fmt.Sprintf("tailscale-user:%d", i), now) {
						t.Fatal("global exhaustion")
					}
				}
			} else {
				for i := 0; i < scriptRunSubjectBurst; i++ {
					if !h.scriptRunLimiter.allow(p.StableSubject(), now) {
						t.Fatal("subject exhaustion")
					}
				}
			}
			var before int
			if e := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&before); e != nil {
				t.Fatal(e)
			}
			for _, op := range []string{"upsert", "set-enabled", "run-now"} {
				for _, phase := range []string{"preview", "apply"} {
					if op == "run-now" && phase == "apply" {
						continue
					}
					req := verifiedOperatorRequest(httptest.NewRequest(http.MethodPost, "/v1/operator/schedules/"+op+"/"+phase, strings.NewReader(`not JSON`)), operatorauth.Operate)
					req.SetPathValue("operation", op)
					req.SetPathValue("phase", phase)
					req.SetPathValue("id", "s-1")
					w := httptest.NewRecorder()
					if op == "run-now" {
						h.handleScheduleRunNow(w, req)
					} else {
						h.handleScheduleManage(w, req)
					}
					if w.Code != 429 || w.Header().Get("Retry-After") == "" || w.Header().Get("Cache-Control") != "no-store" {
						t.Fatalf("%s %s: %d %s", op, phase, w.Code, w.Body.String())
					}
				}
			}
			var after int
			if e := f.store.DB().QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&after); e != nil || after != before {
				t.Fatalf("audit amplified %d -> %d %v", before, after, e)
			}
		})
	}
}
