package store

import (
	"fmt"
	"testing"
)

func TestDiskAlertsPageOrderingAndPagination(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	for i := 0; i < 205; i++ {
		severity := "critical"
		var cleared any
		if i >= 101 {
			severity = "warn"
		}
		if i >= 201 {
			cleared = fmtTime(now)
		}
		if _, err := s.db.Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,cleared_at,last_reading) VALUES(?,?,?,?,?,?,?)`, fmt.Sprintf("alert-%03d", i), req.Targets[0], fmt.Sprintf("condition-%d", i), severity, fmtTime(now), cleared, fmtTime(now)); err != nil {
			t.Fatal(err)
		}
	}
	after := ""
	count := 0
	for page := 0; page < 3; page++ {
		result, err := s.DiskAlertsPageAfter(after)
		if err != nil {
			t.Fatal(err)
		}
		expected := 100
		if page == 2 {
			expected = 5
		}
		if len(result.Items) != expected {
			t.Fatalf("page %d: %d items", page, len(result.Items))
		}
		for _, a := range result.Items {
			if a.ID != fmt.Sprintf("alert-%03d", count) {
				t.Fatalf("ordering at %d: %+v", count, a)
			}
			count++
		}
		after = result.Next
		if (after == "") != (page == 2) {
			t.Fatalf("page %d cursor %q", page, after)
		}
	}
	if _, err := s.DiskAlertsPageAfter("garbage"); err == nil {
		t.Fatal("invalid cursor admitted")
	}
}

func TestDiskAlertMountLabelsBulkBound(t *testing.T) {
	s, req, _ := safeDiskFixture(t)
	labels, err := s.DiskAlertMountLabels([]string{req.Targets[0], "missing-machine"})
	if err != nil || len(labels) != 2 {
		t.Fatalf("labels=%+v err=%v", labels, err)
	}
	if _, err = s.DiskAlertMountLabels(make([]string, DiskAlertsPageSize+1)); err == nil {
		t.Fatal("machine bound not enforced")
	}
}

func TestDiskAlertMountLabelsProjectsOnlyBoundedNames(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	preview, err := s.ScriptRun(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	run, err := s.ScriptRun(req, true, "mount-labels", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	// Only authenticated executor reports contribute labels. Other report data is not projected.
	if _, err = s.db.Exec(`INSERT INTO verification_results(verification_id,job_id,machine_id,rule_id,command,exit_code,passed,verified_at,received_at,producer_id,stdout_excerpt) VALUES('mount-labels',?,?,'script_v1','test',0,1,?,?,?,?)`, run.JobIDs[0], req.Targets[0], fmtTime(now), fmtTime(now), req.Targets[0], `{"operation":{"mounts":[{"mount":"/data","percent":99,"total_bytes":123,"available_bytes":1}]},"private":"never project"}`); err != nil {
		t.Fatal(err)
	}
	labels, err := s.DiskAlertMountLabels([]string{req.Targets[0]})
	if err != nil {
		t.Fatal(err)
	}
	mounts := labels[req.Targets[0]]
	if len(mounts) != 1 || mounts[0].Mount != "/data" || mounts[0].Percent != 0 || mounts[0].TotalBytes != 0 {
		t.Fatalf("overbroad label projection: %+v", mounts)
	}
}
