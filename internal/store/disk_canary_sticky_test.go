package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestDiskCanarySameDayStickyDisagreement(t *testing.T) {
	for _, firstAgreement := range []bool{true, false} {
		name := "disagree then agree"
		if firstAgreement {
			name = "agree then disagree"
		}
		t.Run(name, func(t *testing.T) {
			s, req, now := safeDiskFixture(t)
			machine := req.Targets[0]
			var args map[string]string
			_ = json.Unmarshal(req.Args, &args)
			schedule, err := DiskScheduleTemplate("user", args["policy_id"], args["policy_digest"], machine, 3, 17)
			if err != nil {
				t.Fatal(err)
			}
			schedule.Enabled = false
			schedule.Reason = "daily comparison"
			preview, err := s.ScheduleManage(schedule, "upsert", false, "", diskAdmin())
			if err != nil {
				t.Fatal(err)
			}
			schedule.PreviewDigest = preview.PreviewDigest
			if _, err = s.ScheduleManage(schedule, "upsert", true, "sticky-canary", diskAdmin()); err != nil {
				t.Fatal(err)
			}
			record := func(at, receipt time.Time, agree bool, count int64) {
				t.Helper()
				hub := count
				if !agree {
					hub++
				}
				env := &DiskSafeEnvelope{ReceivedAt: receipt}
				env.Operation.PolicyDigest = args["policy_digest"]
				env.Summary.Scope = "user"
				env.Summary.TS = at.Format(time.RFC3339)
				env.Summary.CandidateBytes = hub
				status := DiskOpsStatus{Preview: env, OwnershipRecords: []DiskOwnership{{Scope: "user", State: "local-owned", Observation: &model.DiskTimerObservation{ReceivedAt: receipt, SummaryAt: at, SummaryCandidateBytes: &count}}}}
				evaluated := now
				if at.UTC().Format("2006-01-02") != now.UTC().Format("2006-01-02") {
					evaluated = at
				}
				if err := s.RecordDiskCanary(machine, status, evaluated); err != nil {
					t.Fatal(err)
				}
			}
			for i := 6; i > 0; i-- {
				day := now.AddDate(0, 0, -i)
				record(day, day, true, 100)
			}
			record(now.Add(-2*time.Minute), now.Add(-2*time.Minute), firstAgreement, 100)
			record(now.Add(-time.Minute), now.Add(-time.Minute), !firstAgreement, 200)
			check := func(wantAgreement bool, wantCount int64) {
				t.Helper()
				c, err := s.DiskCanaryGet(machine, "user", now)
				if err != nil || len(c.Days) != 7 {
					t.Fatalf("canary=%+v err=%v", c, err)
				}
				d := c.Days[6]
				wantAt := now.Add(-time.Minute)
				if wantCount == 400 {
					wantAt = now
				}
				if d.LocalSummaryAt != fmtTime(wantAt) || d.HubSummaryAt != fmtTime(wantAt) {
					t.Fatalf("summary timestamps not refreshed: %+v", d)
				}
				if d.Agreement != wantAgreement || d.LocalCandidateBytes != wantCount || c.Satisfied != wantAgreement {
					t.Fatalf("canary=%+v", c)
				}
			}
			check(false, 200)
			// An older Hub receipt cannot replace the latest counts, even with a newer agent timestamp.
			record(now, now.Add(-3*time.Minute), true, 300)
			check(false, 200)
			if _, err := s.db.Exec(`UPDATE disk_ownership SET state='local-owned' WHERE machine_id=?`, machine); err != nil {
				t.Fatal(err)
			}
			_, err = s.DiskOwnershipManage(DiskOwnershipRequest{MachineID: machine, Scope: "user", Action: "handoff", ExpectedRevision: 1, Reason: "reviewed comparison"}, false, "", diskAdmin())
			if err == nil || !strings.Contains(err.Error(), "canary") {
				t.Fatalf("handoff admitted disagreement: %v", err)
			}
			// Changing the digest restarts this day's agreement rather than carrying disagreement forward.
			if _, err := s.db.Exec(`UPDATE disk_canary_days SET policy_digest='sha256:old-policy' WHERE machine_id=? AND day=?`, machine, now.Format("2006-01-02")); err != nil {
				t.Fatal(err)
			}
			record(now, now, true, 400)
			check(true, 400)
		})
	}
}

func TestDiskCanaryReceiptColumnMigration(t *testing.T) {
	s, _, _ := safeDiskFixture(t)
	if _, err := s.db.Exec(`ALTER TABLE disk_canary_days DROP COLUMN received_at`); err != nil {
		t.Fatal(err)
	}
	if err := addMissingColumns(s.db); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec(`SELECT received_at FROM disk_canary_days`); err != nil {
		t.Fatal(err)
	}
}
