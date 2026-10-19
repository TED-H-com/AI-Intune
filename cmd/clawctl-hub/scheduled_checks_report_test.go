package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestBuildReportScheduledChecksAndCoverage(t *testing.T) {
	f := newJobsFixture(t, "Scheduled worker")
	now := time.Now().UTC().Truncate(time.Second)
	enabled, disabled := true, false
	for _, m := range []struct {
		id      string
		enabled *bool
	}{
		{f.machine.id, &enabled},
		{enrollViaHTTP(t, f.mux, f.store, "New worker").id, &enabled},
		{enrollViaHTTP(t, f.mux, f.store, "Monitor only").id, &disabled},
	} {
		c := model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: now, JobsEnabled: m.enabled, ScriptV1: true}
		if err := f.store.RecordCheckin(m.id, c, now); err != nil {
			t.Fatal(err)
		}
	}
	// A canonical enabled schedule with no job receipt exercises the Hub wiring.
	entry, _ := scriptcatalog.Lookup("fleet-probe-v1")
	req := store.ScheduleRequest{Name: "fleet-daily-health", ScriptID: entry.ID, ScriptSHA256: entry.SHA256, Args: json.RawMessage(`{}`), Targets: []string{f.machine.id}, Cron: "*/5 * * * *", TZ: "UTC", Enabled: false, Reason: "report fixture"}
	actor := store.AuditEntry{AuthSubject: "test-operator", AuthCapability: "operate"}
	preview, err := f.store.ScheduleManage(req, "upsert", false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	created, err := f.store.ScheduleManage(req, "upsert", true, "report-schedule", actor)
	if err != nil {
		t.Fatal(err)
	}
	slot := now.Truncate(5 * time.Minute)
	if _, err := f.store.DB().Exec(`UPDATE schedules SET enabled=1,updated_at=?,next_run_at=? WHERE id=?`, slot.Add(-time.Hour).Format(time.RFC3339), slot.Format(time.RFC3339), created.Schedule.ID); err != nil {
		t.Fatal(err)
	}
	body, err := (&hub{store: f.store}).buildReport(now, now.Add(-24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Scheduled checks", "Scheduled worker — fleet-daily-health: not run", "New worker: not targeted by any enabled schedule"} {
		if !strings.Contains(body, want) {
			t.Fatalf("missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "Monitor only: not targeted") {
		t.Fatal("monitor-only agent listed as untargeted")
	}
}
