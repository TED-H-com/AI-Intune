package store

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
	"time"
)

func TestDiskAlertsThresholdHysteresisUnknown(t *testing.T) {
	for _, threshold := range []int{85, 93} {
		t.Run(string(rune(threshold)), func(t *testing.T) {
			s, req, now := safeDiskFixture(t)
			machine := req.Targets[0]
			v := threshold - 1
			reading := func(value *int, at time.Time) {
				t.Helper()
				if e := s.DiskAlertReading(machine, "pressure", "critical", value, threshold, at); e != nil {
					t.Fatal(e)
				}
			}
			reading(&v, now)
			items, _ := s.DiskAlertsList(machine)
			if len(items) != 0 {
				t.Fatal("below threshold opened")
			}
			v = threshold
			reading(&v, now.Add(time.Minute))
			reading(&v, now.Add(2*time.Minute))
			items, _ = s.DiskAlertsList(machine)
			if len(items) != 1 {
				t.Fatal("episode not deduped")
			}
			v = threshold - 2
			reading(&v, now.Add(3*time.Minute))
			reading(&v, now.Add(9*time.Minute))
			items, _ = s.DiskAlertsList(machine)
			if items[0].ClearedAt != nil {
				t.Fatal("equality cleared")
			}
			v = threshold - 3
			reading(&v, now.Add(10*time.Minute))
			reading(&v, now.Add(14*time.Minute))
			items, _ = s.DiskAlertsList(machine)
			if items[0].ClearedAt != nil {
				t.Fatal("early clear")
			}
			reading(nil, now.Add(15*time.Minute))
			reading(&v, now.Add(16*time.Minute))
			items, _ = s.DiskAlertsList(machine)
			if items[0].ClearedAt != nil {
				t.Fatal("unknown cleared")
			}
			reading(&v, now.Add(21*time.Minute))
			items, _ = s.DiskAlertsList(machine)
			if items[0].ClearedAt == nil {
				t.Fatal("two fresh low readings failed")
			}
			v = threshold
			reading(&v, now.Add(22*time.Minute))
			items, _ = s.DiskAlertsList(machine)
			if len(items) != 2 {
				t.Fatal("new episode missing")
			}
		})
	}
}
func TestDiskOwnershipObservationAndRollback(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	if _, e := s.db.Exec(`DELETE FROM disk_ownership WHERE machine_id=?`, machine); e != nil {
		t.Fatal(e)
	}
	p, e := s.ScriptRun(req, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	if _, e = s.ScriptRun(req, true, "owner-denied", diskAdmin()); e == nil {
		t.Fatal("local-owned apply admitted")
	}
	if _, e = s.db.Exec(`INSERT INTO disk_ownership(machine_id,scope,state,revision,changed_at) VALUES (?,'user','handoff-pending',1,?) ON CONFLICT(machine_id,scope) DO UPDATE SET state='handoff-pending',revision=1,changed_at=excluded.changed_at`, machine, fmtTime(now)); e != nil {
		t.Fatal(e)
	}
	if _, e = s.db.Exec(`UPDATE disk_ownership SET transition_nonce='fixture-transition' WHERE machine_id=? AND scope='user'`, machine); e != nil {
		t.Fatal(e)
	}
	c := healthyCheckin(now.Add(time.Minute))
	c.DiskOpsV2 = true
	c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, Enabled: false, ServiceActive: true, ObservedAt: c.SentAt, TransitionRevision: 1, TransitionNonce: "fixture-transition"}}
	if e = s.RecordCheckin(machine, c, c.SentAt); e != nil {
		t.Fatal(e)
	}
	o, _ := s.DiskOwnershipGet(machine, "user")
	if o.State != "handoff-pending" {
		t.Fatal("running service handed off")
	}
	c.SentAt = now.Add(2 * time.Minute)
	c.DiskTimers[0].ObservedAt = c.SentAt
	c.DiskTimers[0].ServiceActive = false
	if e = s.RecordCheckin(machine, c, c.SentAt); e != nil {
		t.Fatal(e)
	}
	o, _ = s.DiskOwnershipGet(machine, "user")
	if o.State != "hub-owned" {
		t.Fatal(o)
	}
	r := DiskOwnershipRequest{MachineID: machine, Scope: "user", Action: "rollback", ExpectedRevision: o.Revision, Reason: "restore local timer"}
	out, e := s.DiskOwnershipManage(r, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	r.ExpiresAt = out.ExpiresAt
	r.PreviewDigest = out.PreviewDigest
	out, e = s.DiskOwnershipManage(r, true, "rollback-key", diskAdmin())
	if e != nil || out.Ownership.State != "local-owned" {
		t.Fatal(out, e)
	}
	out, e = s.DiskOwnershipManage(r, true, "rollback-key", diskAdmin())
	if e != nil || !out.Replayed {
		t.Fatal("rollback replay", e)
	}
	a := diskAdmin()
	a.AuthMethod = "service_token"
	if _, e = s.DiskOwnershipManage(r, true, "rollback-key", a); e == nil {
		t.Fatal("token replay admitted")
	}
}
func TestDiskAlertAckBoundReasonAndReplay(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	v := 93
	if e := s.DiskAlertReading(req.Targets[0], "mount:digest:critical", "critical", &v, 93, now); e != nil {
		t.Fatal(e)
	}
	items, _ := s.DiskAlertsList("")
	r := DiskAlertAckRequest{ID: items[0].ID, Reason: "Investigating capacity"}
	out, e := s.DiskAlertAcknowledge(r, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	r.ExpiresAt = out.ExpiresAt
	r.PreviewDigest = out.PreviewDigest
	altered := r
	altered.Reason = "changed"
	if _, e = s.DiskAlertAcknowledge(altered, true, "ack", diskAdmin()); e == nil {
		t.Fatal("changed reason admitted")
	}
	if _, e = s.DiskAlertAcknowledge(r, true, "ack", diskAdmin()); e != nil {
		t.Fatal(e)
	}
	out, e = s.DiskAlertAcknowledge(r, true, "ack", diskAdmin())
	if e != nil || !out.Replayed {
		t.Fatal(out, e)
	}
	items, _ = s.DiskAlertsList("")
	if items[0].ClearedAt != nil || items[0].AcknowledgedAt == nil {
		t.Fatal("ack cleared alert")
	}
	raw, _ := json.Marshal(items)
	if len(raw) == 0 {
		t.Fatal("missing ledger")
	}
}

func TestDiskHandoffPreconditionsCanaryAndObservation(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	if _, e := s.db.Exec(`DELETE FROM disk_ownership WHERE machine_id=?`, machine); e != nil {
		t.Fatal(e)
	}
	var args map[string]string
	_ = json.Unmarshal(req.Args, &args)
	schedule, e := DiskScheduleTemplate("user", args["policy_id"], args["policy_digest"], machine, 3, 17)
	if e != nil {
		t.Fatal(e)
	}
	schedule.Enabled = false
	schedule.Reason = "prepare handoff"
	preview, e := s.ScheduleManage(schedule, "upsert", false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	schedule.PreviewDigest = preview.PreviewDigest
	if _, e = s.ScheduleManage(schedule, "upsert", true, "ready-schedule", diskAdmin()); e != nil {
		t.Fatal(e)
	}
	c := healthyCheckin(now)
	c.DiskOpsV2 = true
	c.ScriptV1 = true
	c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, Enabled: true, Active: true, ObservedAt: now}}
	if e = s.RecordCheckin(machine, c, now); e != nil {
		t.Fatal(e)
	}
	r := DiskOwnershipRequest{MachineID: machine, Scope: "user", Action: "handoff", Reason: "reviewed local canary"}
	if _, e = s.DiskOwnershipManage(r, false, "", diskAdmin()); e == nil {
		t.Fatal("missing canary admitted")
	}
	r.OverrideCanary = true
	out, e := s.DiskOwnershipManage(r, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	r.ExpiresAt = out.ExpiresAt
	r.PreviewDigest = out.PreviewDigest
	out, e = s.DiskOwnershipManage(r, true, "handoff", diskAdmin())
	if e != nil || out.Ownership.State != "handoff-pending" {
		t.Fatal(out, e)
	}
	c.DiskTimers[0].TransitionRevision = out.Ownership.Revision
	c.DiskTimers[0].TransitionNonce = out.Ownership.TransitionNonce
	c.SentAt = now.Add(time.Minute)
	c.DiskTimers[0].ObservedAt = c.SentAt
	c.DiskTimers[0].Active = false
	c.DiskTimers[0].Enabled = false
	if e = s.RecordCheckin(machine, c, c.SentAt); e != nil {
		t.Fatal(e)
	}
	owner, e := s.DiskOwnershipGet(machine, "user")
	if e != nil || owner.State != "hub-owned" {
		t.Fatal(owner, e)
	}
	c.SentAt = now.Add(2 * time.Minute)
	c.DiskTimers[0].ObservedAt = c.SentAt
	c.DiskTimers[0].Enabled = true
	if e = s.RecordCheckin(machine, c, c.SentAt); e != nil {
		t.Fatal(e)
	}
	if e = s.ReconcileDiskAlerts(c.SentAt); e != nil {
		t.Fatal(e)
	}
	alerts, _ := s.DiskAlertsList(machine)
	found := false
	for _, a := range alerts {
		if a.ConditionKey == "dual-owner:user" && a.ClearedAt == nil {
			found = true
		}
	}
	if !found {
		t.Fatal("dual ownership not alerted")
	}
	p, e := s.ScriptRun(req, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	if _, e = s.ScriptRun(req, true, "dual-apply", diskAdmin()); e == nil {
		t.Fatal("dual owner apply admitted")
	}
}

func TestDiskCanarySevenPolicyBoundDailyComparisons(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	var args map[string]string
	_ = json.Unmarshal(req.Args, &args)
	schedule, e := DiskScheduleTemplate("user", args["policy_id"], args["policy_digest"], machine, 3, 17)
	if e != nil {
		t.Fatal(e)
	}
	schedule.Enabled = false
	schedule.Reason = "daily comparison"
	p, e := s.ScheduleManage(schedule, "upsert", false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	schedule.PreviewDigest = p.PreviewDigest
	if _, e = s.ScheduleManage(schedule, "upsert", true, "canary-schedule", diskAdmin()); e != nil {
		t.Fatal(e)
	}
	candidate := int64(1048576)
	for i := 0; i < 7; i++ {
		day := now.AddDate(0, 0, i-6)
		env := &DiskSafeEnvelope{}
		env.Operation.PolicyDigest = args["policy_digest"]
		env.Summary.Scope = "user"
		env.Summary.TS = day.Format(time.RFC3339)
		env.Summary.CandidateBytes = candidate
		status := DiskOpsStatus{Preview: env, OwnershipRecords: []DiskOwnership{{Scope: "user", State: "local-owned", Observation: &model.DiskTimerObservation{ReceivedAt: day, SummaryAt: day, SummaryCandidateBytes: &candidate}}}}
		if e = s.RecordDiskCanary(machine, status, day); e != nil {
			t.Fatal(e)
		}
		canary, e := s.DiskCanaryGet(machine, "user", now)
		if e != nil {
			t.Fatal(e)
		}
		if canary.Satisfied != (i == 6) {
			t.Fatal("canary satisfied too soon", i, canary)
		}
	}
	canary, e := s.DiskCanaryGet(machine, "user", now)
	if e != nil || canary.AgreedDays != 7 || len(canary.Days) != 7 {
		t.Fatal(canary, e)
	}
	if _, e = s.db.Exec(`UPDATE disk_canary_days SET policy_digest='sha256:old-policy' WHERE machine_id=?`, machine); e != nil {
		t.Fatal(e)
	}
	canary, e = s.DiskCanaryGet(machine, "user", now)
	if e != nil || canary.Satisfied || canary.AgreedDays != 0 {
		t.Fatal("old policy evidence admitted", canary, e)
	}
}

func TestDiskLocalConsecutiveLockSkipsAlert(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	locked := true
	for i := 0; i < 2; i++ {
		at := now.Add(time.Duration(i+1) * time.Minute)
		c := healthyCheckin(at)
		c.DiskOpsV2 = true
		c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, ObservedAt: at, SummaryAt: at, SummaryLockSkipped: &locked}}
		if e := s.RecordCheckin(machine, c, at); e != nil {
			t.Fatal(e)
		}
		if e := s.ReconcileDiskAlerts(at); e != nil {
			t.Fatal(e)
		}
		items, e := s.DiskAlertsList(machine)
		if e != nil {
			t.Fatal(e)
		}
		found := false
		for _, a := range items {
			if a.ConditionKey == "consecutive-lock-skips:user" && a.ClearedAt == nil {
				found = true
			}
		}
		if found != (i == 1) {
			t.Fatal("lock warning needs two distinct summaries", i, items)
		}
	}
}
