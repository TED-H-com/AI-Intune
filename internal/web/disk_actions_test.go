package web

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

// These fixtures use the production templates and generic public data. They also
// exercise escaping in every new filename-bearing page.
func TestDiskActionScreenshotFixtures(t *testing.T) {
	s, _ := newServer(t)
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/", nil), diskWebPrincipal(true, false, ""))
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	item := diskreport.Item{ID: "archive-1", Category: "duplicate-archives", PrivatePath: "/home/example/archives/release.tar.gz", DisplayPath: "~/…/release.tar.gz", AllocatedBytes: 2 << 30, LogicalBytes: 2 << 30, OwnerUID: 1000, SuggestedAction: "quarantine", Reversible: true, Confidence: "high", Identity: diskreport.Identity{Dev: 2049, Inode: 12345, Size: 2 << 30, MtimeNS: now.Add(-30 * 24 * time.Hour).UnixNano(), CtimeNS: now.UnixNano()}}
	m := store.DiskManifest{ID: "manifest-fixture", MachineID: "machine-fixture", Action: "quarantine", PolicyID: "disk-default", PolicyRevision: 1, Reason: "Retain an obsolete release archive for recovery", Deadline: now.Add(30 * time.Minute), Items: []diskreport.Item{item}}
	preview := store.DiskActionPreview{ManifestID: m.ID, Digest: "sha256:" + strings.Repeat("a", 64), AllocatedBytes: item.AllocatedBytes, LogicalBytes: item.LogicalBytes}
	report := store.DiskReportPage{DiskReportSummary: store.DiskReportSummary{ID: "report-fixture", MachineID: m.MachineID, Digest: preview.Digest, ItemCount: 1}, Items: m.Items}
	restore := m
	restore.Action = "restore"
	restore.ID = "restore-fixture"
	restore.Reason = "Restore the reviewed archive to its original parent"
	fixtures := []struct {
		name, template string
		p              page
	}{
		{"disk-report-viewer", "disk_report.html", page{Title: "Deep disk analysis", DiskReport: &diskReportView{Report: report, Admin: true, Decisions: map[string]string{}}}},
		{"disk-action-confirm", "disk_action.html", page{Title: "Confirm quarantine", DiskAction: &diskActionView{Manifest: m, Preview: preview, RequestJSON: `{"id":"approval-fixture","decision":"approved"}`, Key: "fixture-key", WritesEnabled: true}}},
		{"disk-quarantine-list", "disk_quarantine.html", page{Title: "Quarantine", DiskQuarantine: &diskQuarantineView{Machine: m.MachineID, Admin: true, Items: []store.DiskQuarantineItem{{ManifestID: m.ID, ItemID: item.ID, MachineID: m.MachineID, State: "quarantined", DisplayPath: item.DisplayPath, AllocatedBytes: item.AllocatedBytes, QuarantinedAt: now, ExpiresAt: now.Add(7 * 24 * time.Hour), RemainingSeconds: 6 * 86400}}}}},
		{"disk-restore-preview", "disk_action.html", page{Title: "Confirm restore", DiskAction: &diskActionView{Manifest: restore, Preview: preview, RequestJSON: `{"id":"restore-approval","decision":"approved"}`, Key: "restore-fixture-key", WritesEnabled: true}}},
	}
	for _, f := range fixtures {
		w := httptest.NewRecorder()
		s.render(w, r, f.template, f.p)
		body := w.Body.Bytes()
		if bytes.Contains(body, []byte("type the exact ID to confirm your intent")) {
			t.Fatalf("%s has misleading confirmation text", f.name)
		}
		if w.Code != 200 || !bytes.Contains(body, []byte("</html>")) || bytes.Contains(body, []byte("ZgotmplZ")) {
			t.Fatalf("%s: %s", f.name, body)
		}
		wants := map[string][]string{"disk-report-viewer": {"Approve", "Reject", "delete", "item_ids"}, "disk-action-confirm": {"2.0 GiB", "seven days", "Confirm quarantine"}, "disk-quarantine-list": {"Preview restore", "6 days left", "2.0 GiB"}, "disk-restore-preview": {"never overwrites", "Confirm restore"}}
		for _, want := range wants[f.name] {
			if !bytes.Contains(body, []byte(want)) {
				t.Fatalf("%s missing %s", f.name, want)
			}
		}
		if dir := os.Getenv("CLAWCTL_SCREENSHOT_DIR"); dir != "" {
			if err := os.MkdirAll(dir, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, f.name+".html"), body, 0644); err != nil {
				t.Fatal(err)
			}
		}
		attack := `<img src=x onerror="alert(1)">`
		switch f.template {
		case "disk_report.html":
			f.p.DiskReport.Report.Items = append([]diskreport.Item(nil), f.p.DiskReport.Report.Items...)
			f.p.DiskReport.Report.Items[0].PrivatePath = attack
		case "disk_action.html":
			f.p.DiskAction.Manifest.Items = []diskreport.Item{item}
			f.p.DiskAction.Manifest.Items[0].PrivatePath = attack
			f.p.DiskAction.Manifest.Reason = attack
		case "disk_quarantine.html":
			f.p.DiskQuarantine.Items[0].DisplayPath = attack
		}
		w = httptest.NewRecorder()
		s.render(w, r, f.template, f.p)
		if strings.Contains(w.Body.String(), "<img") || !strings.Contains(w.Body.String(), "&lt;img") {
			t.Fatalf("%s filename escaped incorrectly", f.name)
		}
	}
}

func TestDiskActionHTMLFreshReauthenticationBeforeLookup(t *testing.T) {
	s, st := newServer(t)
	account, err := st.CreateFirstAdmin("example-admin", diskFixturePassword)
	if err != nil {
		t.Fatal(err)
	}
	p := diskWebPrincipal(true, true, account.AccountID)
	for _, path := range []string{"/disk-reports/missing/actions", "/disk-actions/apply", "/machines/missing/quarantine/restore"} {
		w := diskWebRequest(t, s, "POST", path, url.Values{"password": {"incorrect fixture password"}}, p, true)
		if w.Code != 403 || strings.Contains(w.Body.String(), "incorrect fixture password") {
			t.Fatalf("%s reauth gate: %d %s", path, w.Code, w.Body.String())
		}
	}
}

func TestReportHumanRejectConfirmationAndReplay(t *testing.T) {
	s, st := newServer(t)
	policy := createDiskWebPolicy(t, s, st)
	machine := onlineMachine(t, st, "example-device")
	desired, revision, err := st.CreateDesiredState("machine", machine, "script_v1", "disk-deep-report-v1", "{}", "fixture")
	if err != nil {
		t.Fatal(err)
	}
	job, err := st.CreateJob(machine, desired, revision, store.NewJob{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	digest := "sha256:" + strings.Repeat("a", 64)
	meta, _ := json.Marshal(diskreport.Report{Schema: "disk-deep/v1", PolicyID: policy.ID, PolicyDigest: policy.Digest})
	if _, err = st.DB().Exec(`INSERT INTO disk_reports(id,job_id,machine_id,created_at,completed_at,digest,item_count,metadata) VALUES ('report-actions',?,?,?,?,?,1,?)`, job, machine, now, now, digest, string(meta)); err != nil {
		t.Fatal(err)
	}
	item, _ := json.Marshal(diskreport.Item{ID: "candidate-1", Category: "app-update-backups", AllocatedBytes: 4096, LogicalBytes: 4096})
	if _, err = st.DB().Exec(`INSERT INTO disk_report_items VALUES ('report-actions',0,'candidate-1',?,?)`, "/home/example/file<script>.bak", string(item)); err != nil {
		t.Fatal(err)
	}
	principal := diskWebPrincipal(true, false, "")
	w := diskWebRequest(t, s, "POST", "/disk-reports/report-actions/actions", url.Values{"report_digest": {digest}, "single_item": {"reject:candidate-1"}, "reason": {"Keep reviewed rollback backup"}}, principal, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Confirm reject") || strings.Contains(w.Body.String(), "<script>") {
		t.Fatal(w.Code, w.Body.String())
	}
	form := diskWebHidden(t, w.Body.String(), "request", "manifest_id", "idempotency_key")
	var decision store.OpsApprovalDecisionRequest
	if err = json.Unmarshal([]byte(form.Get("request")), &decision); err != nil {
		t.Fatal(err)
	}
	form.Set("confirm_action", "delete")
	w = diskWebRequest(t, s, "POST", "/disk-actions/apply", form, principal, false)
	if w.Code == 303 {
		t.Fatal("wrong typed confirmation applied")
	}
	form.Set("confirm_action", "reject")
	for i := 0; i < 2; i++ {
		w = diskWebRequest(t, s, "POST", "/disk-actions/apply", form, principal, false)
		if w.Code != 303 || w.Header().Get("Location") != "/disk-reports/report-actions" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	a, err := st.OpsApproval(decision.ID, time.Now())
	if err != nil || a.State != "rejected" || a.JobID != "" {
		t.Fatal(a, err)
	}
	w = diskWebRequest(t, s, "GET", "/disk-reports/report-actions", nil, principal, false)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "reject: rejected") {
		t.Fatal("decision absent from report", w.Code, w.Body.String())
	}
}

func TestDiskExpiryHumanDurations(t *testing.T) {
	for _, tc := range []struct {
		seconds int64
		want    string
	}{
		{518400, "6 days left"}, {86400, "1 day left"}, {10800, "in 3 h"}, {9000, "in 3 h"}, {120, "in 2 min"}, {1, "Less than a minute left"}, {0, "Expiry due"}, {-1, "Expiry due"},
	} {
		if got := fmtDiskExpiry(tc.seconds); got != tc.want {
			t.Errorf("%d: %q, want %q", tc.seconds, got, tc.want)
		}
	}
}
