package web

import (
	"bytes"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDiskHandoffScreenshotFixtures(t *testing.T) {
	dir := os.Getenv("CLAWCTL_SCREENSHOT_DIR")
	s, _ := newServer(t)
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/machines/machine-fixture/disk", nil), diskWebPrincipal(true, false, ""))
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	age := int64(3600)
	owner := store.DiskOwnership{MachineID: "machine-fixture", Scope: "user", State: "local-owned", Revision: 1, DisableCommand: store.DiskTimerCommand("user", false), EnableCommand: store.DiskTimerCommand("user", true), Observation: &model.DiskTimerObservation{Scope: "user", Known: true, Installed: true, Enabled: true, Active: true, ObservedAt: now, ReceivedAt: now, ReceiptSequence: 1, SummaryAgeSeconds: &age}}
	critical := store.DiskAlert{ID: "disk-episode-fixture", MachineID: "machine-fixture", ConditionKey: "mount:" + scriptcatalog.Digest([]byte("/")) + ":critical", Severity: "critical", OpenedAt: now}
	status := store.DiskOpsStatus{MachineID: owner.MachineID, Thresholds: store.DefaultDiskPolicy().Thresholds, OwnershipRecords: []store.DiskOwnership{owner}, Alerts: []store.DiskAlert{critical}}
	pending := owner
	pending.State = "rollback-pending"
	pending.EnableCommand = ""
	observation := *owner.Observation
	observation.Enabled = false
	observation.Active = false
	pending.Observation = &observation
	root := owner
	root.Scope = "root"
	root.DisableCommand = store.DiskTimerCommand("root", false)
	root.EnableCommand = store.DiskTimerCommand("root", true)
	fixtures := []struct {
		name, template string
		p              page
	}{
		{"ownership-local-owned", "disk_machine.html", page{Title: "Disk ownership", DiskMachine: &diskMachinePage{Status: status, Canary: map[string]store.DiskCanary{"user": {RequiredDays: 7, AgreedDays: 3, Days: []store.DiskCanaryDay{{Day: "2026-10-01", LocalCandidateBytes: 1048576, HubCandidateBytes: 1048576, Agreement: true}}}}}}},
		{"handoff-confirm", "disk_machine.html", page{Title: "Confirm handoff", DiskMachine: &diskMachinePage{Status: store.DiskOpsStatus{MachineID: owner.MachineID}, OwnershipReview: &store.DiskOwnershipResult{Ownership: root}, Request: `{"machine_id":"machine-fixture","scope":"root","action":"handoff"}`, Digest: "sha256:" + strings.Repeat("a", 64), Key: "fixture-key"}}},
		{"rollback-pending", "disk_machine.html", page{Title: "Rollback pending", DiskMachine: &diskMachinePage{Status: store.DiskOpsStatus{MachineID: owner.MachineID, OwnershipRecords: []store.DiskOwnership{pending}}}}},
		{"alerts-critical", "disk_alerts.html", page{Title: "Disk alerts", Nav: "tenant-disk-alerts", DiskAlerts: &diskAlertsPage{Items: []store.DiskAlert{critical}}}},
	}
	for _, f := range fixtures {
		w := httptest.NewRecorder()
		s.render(w, r, f.template, f.p)
		body := w.Body.Bytes()
		if !bytes.Contains(body, []byte("</html>")) || bytes.Contains(bytes.ReplaceAll(body, []byte("<script data-audit-reason>"), nil), []byte("<script")) || bytes.Contains(body, []byte("ZgotmplZ")) {
			t.Fatalf("invalid fixture %s: %s", f.name, body)
		}
		if dir != "" {
			if e := os.MkdirAll(dir, 0755); e != nil {
				t.Fatal(e)
			}
			if e := os.WriteFile(filepath.Join(dir, f.name+".html"), body, 0644); e != nil {
				t.Fatal(e)
			}
		}
	}
}
func TestDiskAlertPagesEscapeEvidence(t *testing.T) {
	s, _ := newServer(t)
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/tenant/disk-alerts", nil), diskWebPrincipal(true, false, ""))
	w := httptest.NewRecorder()
	s.render(w, r, "disk_alerts.html", page{Title: "Disk alerts", Nav: "tenant-disk-alerts", DiskAlerts: &diskAlertsPage{Items: []store.DiskAlert{{MachineID: "fixture", ConditionKey: `<script>alert(1)</script>`, AcknowledgementReason: `<img src=x onerror=alert(1)>`}}}})
	if strings.Contains(w.Body.String(), "<script>") || strings.Contains(w.Body.String(), "<img src=x") {
		t.Fatal("unescaped evidence")
	}
}

func TestDiskOwnershipUIRequiresLabeledExactConfirmation(t *testing.T) {
	s, st := newServer(t)
	id := onlineMachine(t, st, "example-device")
	now := time.Now().UTC()
	if _, e := st.DB().Exec(`INSERT INTO disk_ownership(machine_id,scope,state,revision,changed_at) VALUES (?,'user','hub-owned',1,?) ON CONFLICT(machine_id,scope) DO UPDATE SET state='hub-owned',revision=1`, id, now.Format(time.RFC3339)); e != nil {
		t.Fatal(e)
	}
	principal := diskWebPrincipal(true, false, "")
	page := diskWebRequest(t, s, "GET", "/machines/"+id+"/disk", nil, principal, false)
	for _, required := range []string{"Quarantine and restore", "/machines/" + id + "/quarantine", "<h2>Ownership</h2>", "<h2>Alerts</h2>"} {
		if page.Code != 200 || !strings.Contains(page.Body.String(), required) {
			t.Fatalf("combined disk page missing %q (status %d)", required, page.Code)
		}
	}
	path := "/machines/" + id + "/disk/ownership"
	w := diskWebRequest(t, s, "POST", path, url.Values{"action": {"rollback"}, "scope": {"user"}, "revision": {"1"}, "reason": {"wait for Hub cleanup"}}, principal, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `name="confirm_id"`) || strings.Contains(w.Body.String(), "enable --now") {
		t.Fatal("review missing confirmation or exposed re-enable command", w.Code, w.Body.String())
	}
	apply := diskWebHidden(t, w.Body.String(), "action", "request", "digest", "key")
	apply.Set("confirm_id", "wrong-id")
	w = diskWebRequest(t, s, "POST", path, apply, principal, false)
	if w.Code != 400 {
		t.Fatal("wrong confirmation admitted", w.Code)
	}
	apply.Set("confirm_id", id)
	w = diskWebRequest(t, s, "POST", path, apply, principal, false)
	if w.Code != 303 {
		t.Fatal("confirmed rollback failed", w.Code, w.Body.String())
	}
}
func TestDiskAlertsUIUsesPerRowActionsLabelsAndBadges(t *testing.T) {
	s, _ := newServer(t)
	principal := diskWebPrincipal(true, false, "")
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/tenant/disk-alerts", nil), principal)
	at := time.Now().UTC()
	mount := "/data/<script>"
	key := "mount:" + scriptcatalog.Digest([]byte(mount)) + ":critical"
	alerts := []store.DiskAlert{{ID: "open-alert", MachineID: "fixture", ConditionKey: key, Severity: "critical"}, {ID: "cleared-alert", MachineID: "fixture", ConditionKey: key, Severity: "critical", ClearedAt: &at}}
	table := diskAlertTable(alerts, true, map[string][]store.DiskMountUsage{"fixture": {{Mount: mount}}})
	w := httptest.NewRecorder()
	if e := s.tmpl.ExecuteTemplate(w, "disk_alert_table", table); e != nil {
		t.Fatal(e)
	}
	body := w.Body.String()
	if strings.Count(body, `action="/tenant/disk-alerts/ack/preview"`) != 1 || !strings.Contains(body, `value="open-alert"`) || strings.Contains(body, "Alert ID") || strings.Contains(body, scriptcatalog.Digest([]byte(mount))) || !strings.Contains(body, "disk usage critical") || !strings.Contains(body, "disk-error") || strings.Contains(body, "<script>") {
		t.Fatal(body)
	}
	w = httptest.NewRecorder()
	s.render(w, r, "disk_machine.html", page{Title: "Disk", DiskMachine: &diskMachinePage{Status: store.DiskOpsStatus{MachineID: "fixture"}}})
	if !strings.Contains(w.Body.String(), "Warning 85% · critical 93%") || strings.Contains(w.Body.String(), "Warning 0%") {
		t.Fatal("effective defaults missing")
	}
}
