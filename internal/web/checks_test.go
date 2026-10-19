package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/docs/runbooks"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/tailnet"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChecksPreviewFiveDisabledSchedules(t *testing.T) {
	s, st := newServer(t)
	id := onlineMachine(t, st, "Sample machine")
	enabled := true
	now := time.Now().UTC()
	if err := st.RecordCheckin(id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: now, JobsEnabled: &enabled, ScriptV1: true}, now); err != nil {
		t.Fatal(err)
	}
	p := scheduleWebPrincipal()
	w := diskWebRequest(t, s, "POST", "/checks/schedules/preview", url.Values{"target": {id}}, p, false)
	body := w.Body.String()
	if w.Code != 200 || strings.Count(body, `name="request"`) != 5 || !strings.Contains(body, "</html>") {
		t.Fatal(w.Code, body)
	}
	if dir := os.Getenv("CLAWCTL_SCREENSHOT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "disabled-schedules.html"), []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	// Every form uses the existing apply route and an independently bound preview.
	for _, part := range strings.Split(body, `<form class="disk-form"`)[1:] {
		form := diskWebHidden(t, part, "request", "operation", "preview_digest", "idempotency_key", "expected_revision", "confirm")
		var req store.ScheduleRequest
		if err := json.Unmarshal([]byte(form.Get("request")), &req); err != nil {
			t.Fatal(err)
		}
		if req.Enabled || req.CatchUp || len(req.Targets) != 1 || req.Targets[0] != id {
			t.Fatal(req)
		}
		altered := req
		altered.Enabled = true
		raw, _ := json.Marshal(altered)
		bad := url.Values{}
		for k, v := range form {
			bad[k] = v
		}
		bad.Set("request", string(raw))
		if got := diskWebRequest(t, s, "POST", "/tenant/schedules/apply", bad, p, false); got.Code < 400 {
			t.Fatal("enabled tampering accepted")
		}
		if got := diskWebRequest(t, s, "POST", "/tenant/schedules/apply", form, p, false); got.Code != 303 {
			t.Fatal(got.Code, got.Body.String())
		}
	}
	schedules, err := st.ScheduleList()
	if err != nil || len(schedules) != 5 {
		t.Fatal(schedules, err)
	}
	for _, v := range schedules {
		if v.Enabled || v.CatchUp {
			t.Fatal(v)
		}
	}
	for _, form := range []url.Values{{"target": {id, id}}, {"target": {"missing"}}, {"target": {id}, "enabled": {"true"}}} {
		if got := diskWebRequest(t, s, "POST", "/checks/schedules/preview", form, p, false); got.Code < 400 {
			t.Fatal("invalid target or field allowed", got.Code)
		}
	}
	if got := diskWebRequest(t, s, "POST", "/checks/schedules/preview", url.Values{"target": {id}}, diskWebPrincipal(false, false, ""), false); got.Code != 403 {
		t.Fatal(got.Code)
	}
}
func TestChecksExampleCatalogBinding(t *testing.T) {
	var reqs []store.ScheduleRequest
	if err := json.Unmarshal(runbooks.Phase0Schedules, &reqs); err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 5 {
		t.Fatal(len(reqs))
	}
	for _, r := range reqs {
		e, ok := scriptcatalog.Lookup(r.ScriptID)
		if !ok || e.SHA256 != r.ScriptSHA256 || r.Enabled || r.CatchUp {
			t.Fatal(r)
		}
	}
}
func TestChecksSSRLatestAndRedaction(t *testing.T) {
	s, st := newServer(t)
	s.SetTailnetStatus(tailnet.Status{})
	id := onlineMachine(t, st, "Sample appliance")
	secret := "ocid1.tenancy.secret private-peer user@example.invalid token=secret"
	desired, rev, err := st.CreateDesiredState("machine", id, scriptcatalog.Kind, "network-watch-v1", `{}`, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	job, err := st.CreateJob(id, desired, rev, store.NewJob{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`UPDATE desired_state SET spec='{"kind":"script_v1","script_id":"network-watch-v1"}' WHERE desired_id=?`, desired); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	lease, err := st.ClaimJob(job, id, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.AdvanceJobByAgent(job, id, lease, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]any{"schema_version": 1, "status": "warn", "summary": secret, "metrics": map[string]any{"online_peer_count": 2, "expected_offline_count": 1, "derp_only_count": 1, "dns_failure_count": 0, "cloudflared_active": true}, "findings": []any{map[string]any{"reason": "expected_peers_offline", "peer": secret}}})
	if _, err = st.DB().Exec(`INSERT INTO verification_results(verification_id,job_id,machine_id,rule_id,command,stdout_excerpt,passed,verified_at) VALUES ('check-proof',?,?,?,'',?,1,?)`, job, id, scriptcatalog.Kind, string(raw), time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/checks", "/machines/" + id} {
		body := get(t, s, path)
		for _, want := range []string{"Checks / 檢查", "Needs attention", "expected peers are offline", "Peers online"} {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %s", path, want)
			}
		}
		for _, bad := range []string{"ocid1.tenancy.secret", "private-peer", "user@example.invalid", "token=secret"} {
			if strings.Contains(body, bad) {
				t.Fatal("identity leaked", bad)
			}
		}
		if dir := os.Getenv("CLAWCTL_SCREENSHOT_DIR"); dir != "" {
			name := "checks.html"
			if path != "/checks" {
				name = "machine-checks.html"
			}
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A newer run without usable evidence replaces an older warning; no stale green.
	newDesired, newRev, err := st.CreateDesiredState("machine", id, scriptcatalog.Kind, "network-watch-v1", `{}`, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := st.CreateJob(id, newDesired, newRev, store.NewJob{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`UPDATE desired_state SET spec='{"kind":"script_v1","script_id":"network-watch-v1"}' WHERE desired_id=?`, newDesired); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`UPDATE jobs SET created_at=? WHERE job_id=?`, time.Now().Add(time.Minute).UTC().Format(time.RFC3339Nano), newer); err != nil {
		t.Fatal(err)
	}
	if body := get(t, s, "/checks"); !strings.Contains(body, "Awaiting result") {
		t.Fatal(body)
	}
}
