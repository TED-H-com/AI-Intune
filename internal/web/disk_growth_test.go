package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDiskGrowthPolicyFormAndRendering(t *testing.T) {
	form := diskWebEditForm()
	form.Set("growth_gb_per_hour", "25")
	form.Set("growth_window_minutes", "60")
	r := httptest.NewRequest("POST", "/", nil)
	r.PostForm = form
	req, err := diskPolicyFromForm(r)
	if err != nil {
		t.Fatal(err)
	}
	var p store.DiskPolicy
	json.Unmarshal(req.Body, &p)
	if p.Growth == nil || p.Growth.GBPerHour != 25 || p.Growth.WindowMinutes != 60 {
		t.Fatalf("policy %+v", p.Growth)
	}
	hours := 2.0
	g := store.DiskGrowth{Known: true, GBPerHour: 12, WindowMinutes: 30, CoverageMinutes: 30, Samples: 4, TimeToFullHours: &hours}
	label := diskAlertConditionLabel("growth:"+scriptcatalog.Digest([]byte("/data")), []store.DiskMountUsage{{Mount: "/data", Growth: &g}})
	for _, want := range []string{"/data", "12.00 GB/hour", "30 min window", "2.0 hours to full"} {
		if !strings.Contains(label, want) {
			t.Fatalf("missing %s in %s", want, label)
		}
	}
	s, _ := newServer(t)
	w := httptest.NewRecorder()
	if err := s.tmpl.ExecuteTemplate(w, "disk_growth_panel", []store.DiskGrowth{g}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Body.String(), "Top growing mount") || !strings.Contains(w.Body.String(), "Configure growth alerts") || !strings.Contains(w.Body.String(), "2.0 hours to full") || strings.Contains(w.Body.String(), "%!") {
		t.Fatal(w.Body.String())
	}
}

func TestDiskGrowthScreenshotFixtures(t *testing.T) {
	dir := os.Getenv("CLAWCTL_GROWTH_SCREENSHOT_DIR")
	if dir == "" {
		t.Skip("optional screenshot fixtures")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, _ := newServer(t)
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/tenant/disk-alerts", nil), diskWebPrincipal(true, false, ""))
	hours := 6.2
	g := store.DiskGrowth{Mount: "/", Known: true, Sustained: true, GBPerHour: 12, WindowMinutes: 30, CoverageMinutes: 30, Samples: 4, TimeToFullHours: &hours}
	fixtures := []struct {
		name, template string
		data           page
	}{
		{"growth-policy", "disk_policies.html", page{Title: "Disk policies", DiskPolicies: &diskPoliciesPage{Edit: store.DefaultDiskPolicy(), ID: "disk-default", WritesEnabled: true}}},
		{"growth-alerts", "disk_alerts.html", page{Title: "Disk alerts", DiskAlerts: &diskAlertsPage{Items: []store.DiskAlert{{ID: "example-alert", MachineID: "example-device", ConditionKey: "growth:" + scriptcatalog.Digest([]byte("/")), Severity: "critical"}}, Labels: map[string][]store.DiskMountUsage{"example-device": {{Mount: "/", Growth: &g}}}}}},
		{"growth-machine", "disk_machine.html", page{Title: "Disk · example-device", DiskMachine: &diskMachinePage{Status: store.DiskOpsStatus{MachineID: "example-device", Growth: []store.DiskGrowth{g}}}}},
	}
	for _, f := range fixtures {
		w := httptest.NewRecorder()
		s.render(w, r, f.template, f.data)
		if !strings.Contains(w.Body.String(), "</html>") {
			t.Fatal("incomplete fixture", f.name)
		}
		if err := os.WriteFile(filepath.Join(dir, f.name+".html"), w.Body.Bytes(), 0600); err != nil {
			t.Fatal(err)
		}
	}
}
