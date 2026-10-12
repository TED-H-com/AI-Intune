package web

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func scheduleWebPrincipal() operatorauth.Principal {
	p := diskWebPrincipal(false, false, "")
	names, _ := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	p.GrantedCapabilities.Operate = names.Operate
	p.AuthorizedCapability = names.Operate
	return p
}
func scheduleTestForm(machine string) url.Values {
	return url.Values{"name": {"daily-probe"}, "script_id": {"fleet-probe-v1"}, "args": {"{}"}, "targets": {machine}, "cron": {"0 12 * * *"}, "tz": {"America/New_York"}, "enabled": {"true"}, "expected_revision": {"0"}, "reason": {"daily fleet health"}, "operation": {"upsert"}}
}
func TestScheduleWebPreviewApplyAndRunNow(t *testing.T) {
	s, st := newServer(t)
	machine := onlineMachine(t, st, "Probe machine")
	enabled := true
	now := time.Now().UTC()
	if err := st.RecordCheckin(machine, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: now, JobsEnabled: &enabled, ScriptV1: true}, now); err != nil {
		t.Fatal(err)
	}
	p := scheduleWebPrincipal()
	w := diskWebRequest(t, s, "POST", schedulesBack+"/preview", scheduleTestForm(machine), p, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") || !strings.Contains(w.Body.String(), "Next 3 runs") {
		t.Fatal(w.Code, w.Body.String())
	}
	apply := diskWebHidden(t, w.Body.String(), "request", "operation", "preview_digest", "idempotency_key", "expected_revision", "confirm")
	bad := url.Values{}
	for k, v := range apply {
		bad[k] = v
	}
	bad.Set("preview_digest", "stale")
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", bad, p, false)
	if w.Code < 400 {
		t.Fatal("stale digest accepted")
	}
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, false)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	location := w.Header().Get("Location")
	items, err := st.ScheduleList()
	if err != nil || len(items) != 1 || items[0].TZ != "America/New_York" {
		t.Fatal(items, err)
	}
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, false)
	if w.Code != 303 || w.Header().Get("Idempotency-Replayed") != "true" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = diskWebRequest(t, s, "POST", location+"/run-now", url.Values{}, p, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	run := diskWebHidden(t, w.Body.String(), "idempotency_key", "confirm")
	for i := 0; i < 2; i++ {
		w = diskWebRequest(t, s, "POST", location+"/run-now", run, p, false)
		if w.Code != 303 {
			t.Fatal(w.Code, w.Body.String())
		}
		if i == 1 && w.Header().Get("Idempotency-Replayed") != "true" {
			t.Fatal("no replay header")
		}
	}
	ids, err := st.ScheduleJobIDs(items[0].ID)
	if err != nil || len(ids) != 1 {
		t.Fatal(ids, err)
	}
	for _, path := range []string{schedulesBack, location, location + "/edit"} {
		w = diskWebRequest(t, s, "GET", path, nil, p, false)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "</html>") {
			t.Fatal(path, w.Code, w.Body.String())
		}
	}
	toggle := url.Values{"operation": {"set-enabled"}, "id": {items[0].ID}, "expected_revision": {"1"}, "enabled": {"false"}, "reason": {"maintenance"}}
	w = diskWebRequest(t, s, "POST", schedulesBack+"/preview", toggle, p, false)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	apply = diskWebHidden(t, w.Body.String(), "request", "operation", "preview_digest", "idempotency_key", "expected_revision", "confirm")
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, false)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	got, err := st.ScheduleGet(items[0].ID)
	if err != nil || got.Enabled || got.TZ != "America/New_York" {
		t.Fatal(got, err)
	}
	// The old configuration preview is now revision-stale (with a fresh key).
	apply.Set("idempotency_key", "revision-stale")
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, false)
	if w.Code < 400 {
		t.Fatal("stale revision accepted")
	}
}
func TestScheduleWebPermissionsAndValidation(t *testing.T) {
	s, st := newServer(t)
	machine := onlineMachine(t, st, "Probe machine")
	p := scheduleWebPrincipal()
	form := scheduleTestForm(machine)
	for _, principal := range []operatorauth.Principal{{}, diskWebPrincipal(false, false, "")} {
		w := diskWebRequest(t, s, "POST", schedulesBack+"/preview", form, principal, false)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	mux := http.NewServeMux()
	s.Routes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", schedulesBack, nil))
	if w.Code != 403 {
		t.Fatal("unauthenticated list", w.Code)
	}
	form.Set("script_id", "bat-sweep-report-v1")
	w = diskWebRequest(t, s, "POST", schedulesBack+"/preview", form, p, false)
	if w.Code != 403 {
		t.Fatal("write allowed", w.Code)
	}
	form = scheduleTestForm(machine)
	form.Set("args", `{"unknown":true}`)
	w = diskWebRequest(t, s, "POST", schedulesBack+"/preview", form, p, false)
	if w.Code < 400 || !strings.Contains(w.Body.String(), "role=\"alert\"") {
		t.Fatal("no inline schema error", w.Code, w.Body.String())
	}
	form = scheduleTestForm(machine)
	form.Add("name", "duplicate")
	w = diskWebRequest(t, s, "POST", schedulesBack+"/preview", form, p, false)
	if w.Code != 400 {
		t.Fatal("duplicate accepted")
	}
}

func TestScheduleWebAdminFreshReauthentication(t *testing.T) {
	s, st := newServer(t)
	id := onlineMachine(t, st, "Admin probe")
	account, err := st.CreateFirstAdmin("schedule-admin", diskFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	p := diskWebPrincipal(true, true, account.AccountID)
	// Boundary authorizes a read schedule as Operate even for a local admin.
	names, _ := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	p.GrantedCapabilities.Operate = names.Operate
	p.AuthorizedCapability = names.Operate
	form := scheduleTestForm(id)
	form.Del("enabled")
	w := diskWebRequest(t, s, "POST", schedulesBack+"/preview", form, p, true)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	apply := diskWebHidden(t, w.Body.String(), "request", "operation", "preview_digest", "idempotency_key", "expected_revision", "confirm")
	apply.Set("password", "wrong-password")
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, true)
	if w.Code != 403 || strings.Contains(w.Body.String(), "wrong-password") {
		t.Fatal("reauth failed open", w.Code)
	}
	apply.Set("password", diskFixturePassword)
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, false)
	if w.Code != 403 {
		t.Fatal("MFA bypassed", w.Code)
	}
	w = diskWebRequest(t, s, "POST", schedulesBack+"/apply", apply, p, true)
	if w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestSchedulePreviewTargetReasonsKeepLines(t *testing.T) {
	s, st := newServer(t)
	first := onlineMachine(t, st, "First target")
	second := onlineMachine(t, st, "Second target")
	disabled := false
	now := time.Now().UTC()
	for _, id := range []string{first, second} {
		if err := st.RecordCheckin(id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: now, JobsEnabled: &disabled, ScriptV1: true}, now); err != nil {
			t.Fatal(err)
		}
	}
	form := scheduleTestForm(first)
	form["targets"] = []string{first, second}
	w := diskWebRequest(t, s, "POST", schedulesBack+"/preview", form, scheduleWebPrincipal(), false)
	body := w.Body.String()
	if w.Code != 400 || !strings.Contains(body, `white-space: pre-line`) {
		t.Fatal(w.Code, body)
	}
	for _, name := range []string{"First target", "Second target"} {
		if !strings.Contains(body, name+": jobs disabled in latest check-in") {
			t.Fatal(body)
		}
	}
}

func TestScriptPreviewErrorKeepsLinesAndEscapesNames(t *testing.T) {
	s, _ := newServer(t)
	w := httptest.NewRecorder()
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/", nil), scheduleWebPrincipal())
	s.diskOpsError(w, r, &store.OperatorRequestError{Code: "SCRIPT_INVALID", Detail: "<first>: retired\nsecond: no check-in yet"}, "/machines")
	body := w.Body.String()
	if w.Code != 400 || !strings.Contains(body, `white-space: pre-line`) || !strings.Contains(body, "&lt;first&gt;: retired\nsecond: no check-in yet") {
		t.Fatal(w.Code, body)
	}
}
