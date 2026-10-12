package web

import (
	"bytes"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeepDiskScreenshotFixtures(t *testing.T) {
	dir := os.Getenv("CLAWCTL_SCREENSHOT_DIR")
	s, _ := newServer(t)
	r := operatorauth.WithPrincipal(httptest.NewRequest("GET", "/disk-reports/report-fixture", nil), diskWebPrincipal(true, false, ""))
	report := store.DiskReportPage{DiskReportSummary: store.DiskReportSummary{ID: "report-fixture", MachineID: "machine-fixture", CreatedAt: "2026-10-01T12:00:00Z", Digest: "sha256:" + strings.Repeat("a", 64), ItemCount: 3, Report: diskreport.Report{Partial: true, Truncated: true, InaccessibleRoots: []string{"reviewed-root-3"}, Notices: []string{"Access times are weak under relatime/noatime.", "Reviewed roots/subtrees skipped: no O_NOATIME permission"}, Excluded: map[string]diskreport.Aggregate{"protected": {Count: 7, AllocatedBytes: 10485760}}}}, Items: []diskreport.Item{
		{ID: "archive-1", Category: "duplicate-archives", PrivatePath: "/home/example/archives/very-long-fixture-directory-name-that-wraps-at-the-viewport-boundary/another-long-directory/release.tar.gz", AllocatedBytes: 2147483648, LogicalBytes: 2147483648, LastUsed: "2026-08-01T12:00:00Z", LastUsedSource: "atime", EvidenceStrength: "weak", OwnerApp: "unknown", OwnerUID: 1000, Confidence: "high", SuggestedAction: "quarantine", Reversible: true},
		{ID: "backup-1", Category: "app-update-backups", PrivatePath: "/home/example/app/tool.bak", AllocatedBytes: 524288000, LogicalBytes: 524288000, LastUsed: "2026-09-01T12:00:00Z", LastUsedSource: "atime", EvidenceStrength: "weak", OwnerApp: "unknown", OwnerUID: 1000, Confidence: "low", SuggestedAction: "investigate", ExclusionReason: "generation references unknown; review required"},
		{ID: "session-1", Category: "agent-session-stores", DisplayPath: "~/…/session.json", AllocatedBytes: 1048576, LogicalBytes: 1048576, LastUsedSource: "atime", EvidenceStrength: "weak", OwnerApp: "unknown", OwnerUID: 1000, Confidence: "low", SuggestedAction: "investigate", AgeBucket: "90+ days"},
	}}
	status := store.DiskOpsStatus{MachineID: "machine-fixture", Thresholds: store.DefaultDiskPolicy().Thresholds, Mounts: []store.DiskMountUsage{{Mount: "/", TotalBytes: 107374182400, AvailableBytes: 12884901888, Percent: 88}}}
	fixtures := []struct {
		name, template string
		p              page
	}{
		{"disk-deep-analysis", "disk_machine.html", page{Title: "Disk", DiskMachine: &diskMachinePage{Status: status, Policies: []store.OpsPolicy{{ID: "disk-default", Revision: 1}}, Reports: []store.DiskReportSummary{report.DiskReportSummary}}}},
		{"disk-deep-review", "disk_machine.html", page{Title: "Review deep analysis", DiskMachine: &diskMachinePage{Status: status, ReadOnly: true, Review: "Run deep analysis (read only)", Request: `{"script_id":"disk-deep-report-v1","targets":["machine-fixture"]}`, Digest: report.Digest, Key: "fixture-key", Operation: "script"}}},
		{"disk-report-viewer", "disk_report.html", page{Title: "Deep disk analysis", DiskReport: &diskReportView{Report: report}}},
	}
	for _, f := range fixtures {
		w := httptest.NewRecorder()
		s.render(w, r, f.template, f.p)
		body := w.Body.Bytes()
		if !bytes.Contains(body, []byte("</html>")) || bytes.Contains(body, []byte("<script")) || bytes.Contains(body, []byte("ZgotmplZ")) {
			t.Fatalf("invalid fixture %s: %s", f.name, body)
		}
		if f.name == "disk-report-viewer" {
			for _, want := range []string{"2.0 GiB", "Partial report", "Scan budget reached", "human admin", `disabled`, "disk-report-scroll", "disk-report-table", "disk-report-filters", "skipped: no O_NOATIME permission", "Excluded protected", "weak"} {
				if !bytes.Contains(body, []byte(want)) {
					t.Fatalf("missing %s", want)
				}
			}
		}
		if f.name == "disk-deep-review" && bytes.Contains(body, []byte("disabled>Apply")) {
			t.Fatal("read report wrongly blocked by writes flag")
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

func TestDeepViewerHumanAdminPathBoundaryAndFilters(t *testing.T) {
	s, st := newServer(t)
	id := onlineMachine(t, st, "example-device")
	desired, revision, e := st.CreateDesiredState("machine", id, "script_v1", "disk-deep-report-v1", "{}", "fixture")
	if e != nil {
		t.Fatal(e)
	}
	job, e := st.CreateJob(id, desired, revision, store.NewJob{})
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	meta, _ := json.Marshal(diskreport.Report{Schema: "disk-deep/v1", Items: []diskreport.Item{}})
	if _, e = st.DB().Exec(`INSERT INTO disk_reports(id,job_id,machine_id,created_at,completed_at,digest,item_count,metadata) VALUES ('report-fixture',?,?,?,?,?,2,?)`, job, id, now, now, "sha256:"+strings.Repeat("a", 64), string(meta)); e != nil {
		t.Fatal(e)
	}
	for n, confidence := range []string{"high", "low"} {
		item := diskreport.Item{ID: "candidate-" + confidence, Category: "app-update-backups", Confidence: confidence, EvidenceStrength: "weak", SuggestedAction: "investigate"}
		body, _ := json.Marshal(item)
		if _, e = st.DB().Exec(`INSERT INTO disk_report_items VALUES ('report-fixture',?,?,?,?)`, n, item.ID, "/home/private-account/proj\u202eect/"+confidence+"\u200b.bak", string(body)); e != nil {
			t.Fatal(e)
		}
	}
	for _, admin := range []bool{false, true} {
		w := diskWebRequest(t, s, "GET", "/disk-reports/report-fixture", nil, diskWebPrincipal(admin, false, ""), false)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), "\u202e") || strings.Contains(w.Body.String(), "\u200b") {
			t.Fatal("viewer displayed unsafe Unicode path")
		}
		if strings.Contains(w.Body.String(), "private-account") != admin {
			t.Fatal("path reveal boundary", admin)
		}
	}
	w := diskWebRequest(t, s, "GET", "/disk-reports/report-fixture?confidence=high&limit=1", nil, diskWebPrincipal(false, false, ""), false)
	if w.Code != 200 || strings.Contains(w.Body.String(), "candidate-low") || !strings.Contains(w.Body.String(), "candidate-high") {
		t.Fatal("filter failed", w.Code, w.Body.String())
	}
}
