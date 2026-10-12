package store

import (
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
	"time"
)

func TestDiskRollbackWaitsForClaimedJob(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	p, e := s.ScriptRun(req, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	req.PreviewDigest = p.PreviewDigest
	run, e := s.ScriptRun(req, true, "claimed-cleanup", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	lease, e := s.ClaimJob(run.JobIDs[0], machine, now, time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	owner, e := s.DiskOwnershipGet(machine, "user")
	if e != nil {
		t.Fatal(e)
	}
	r := DiskOwnershipRequest{MachineID: machine, Scope: "user", Action: "rollback", Reason: "return apply to local timer", ExpectedRevision: owner.Revision}
	preview, e := s.DiskOwnershipManage(r, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	r.ExpiresAt = preview.ExpiresAt
	r.PreviewDigest = preview.PreviewDigest
	out, e := s.DiskOwnershipManage(r, true, "rollback-claimed", diskAdmin())
	if e != nil || out.Ownership.State != "rollback-pending" || out.Ownership.EnableCommand != "" {
		t.Fatal(out, e)
	}
	if e = s.ReconcileDiskOwnership(now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	owner, _ = s.DiskOwnershipGet(machine, "user")
	if owner.State != "rollback-pending" || owner.EnableCommand != "" {
		t.Fatal("claimed job released ownership", owner)
	}
	if _, e = s.AdvanceJobByAgent(run.JobIDs[0], machine, lease, deploy.Start, now); e == nil {
		t.Fatal("claimed job started after rollback")
	}
	if _, e = s.AdvanceJobByAgent(run.JobIDs[0], machine, lease, deploy.Reject, now.Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	owner, e = s.DiskOwnershipGet(machine, "user")
	if e != nil || owner.State != "local-owned" || owner.EnableCommand == "" {
		t.Fatal(owner, e)
	}
	replay, e := s.DiskOwnershipManage(r, true, "rollback-claimed", diskAdmin())
	if e != nil || !replay.Replayed {
		t.Fatal(replay, e)
	}
	var n int
	if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='disk_ownership_rollback' AND idempotency_key='rollback-claimed' AND detail='idempotent replay'`).Scan(&n); e != nil || n != 1 {
		t.Fatal("replay not audited", n, e)
	}
}

func TestDiskHandoffRequiresEchoOnHubReceiptDespiteClockSkew(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	if _, e := s.db.Exec(`UPDATE disk_ownership SET state='handoff-pending',revision=9,transition_nonce='hub-challenge',changed_at=? WHERE machine_id=? AND scope='user'`, diskReceiptTime(now), machine); e != nil {
		t.Fatal(e)
	}
	send := func(received, observed time.Time, revision int64, nonce string, enabled bool) {
		t.Helper()
		c := healthyCheckin(received)
		c.DiskOpsV2 = true
		c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, ObservedAt: observed, Enabled: enabled, TransitionRevision: revision, TransitionNonce: nonce, ReceivedAt: now.AddDate(1, 0, 0), ReceiptSequence: 999999}}
		if e := s.RecordCheckin(machine, c, received); e != nil {
			t.Fatal(e)
		}
	}
	send(now.Add(time.Minute), now.Add(24*time.Hour), 0, "", false)
	owner, _ := s.DiskOwnershipGet(machine, "user")
	if owner.State != "handoff-pending" {
		t.Fatal("delayed pre-transition evidence completed handoff")
	}
	send(now.Add(2*time.Minute), now.Add(48*time.Hour), 8, "old-challenge", false)
	owner, _ = s.DiskOwnershipGet(machine, "user")
	if owner.State != "handoff-pending" {
		t.Fatal("old nonce completed handoff")
	}
	send(now.Add(3*time.Minute), now.Add(-24*time.Hour), 9, "hub-challenge", false)
	owner, _ = s.DiskOwnershipGet(machine, "user")
	if owner.State != "hub-owned" {
		t.Fatal("Hub receipt incorrectly used skewed agent clock", owner)
	}
	if !owner.Observation.ReceivedAt.Equal(now.Add(3*time.Minute)) || owner.Observation.ReceiptSequence == 999999 {
		t.Fatal("trusted forged receipt", owner.Observation)
	}
	send(now.Add(4*time.Minute), now.Add(-48*time.Hour), 9, "hub-challenge", true)
	owner, _ = s.DiskOwnershipGet(machine, "user")
	if !owner.Observation.Enabled {
		t.Fatal("evidence ordered by agent time instead of receipt")
	}
}

func TestDiskTimerRateAndBoundedRetention(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	send := func(at time.Time) {
		t.Helper()
		c := healthyCheckin(at)
		c.DiskOpsV2 = true
		c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, ObservedAt: now}}
		if e := s.RecordCheckin(machine, c, at); e != nil {
			t.Fatal(e)
		}
	}
	send(now)
	for i := 1; i < 30; i++ {
		send(now.Add(time.Duration(i) * time.Second))
	}
	var n int
	if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_timer_observations WHERE machine_id=?`, machine).Scan(&n); e != nil || n != 1 {
		t.Fatal("ingestion not bounded", n, e)
	}
	for i := 1; i < 25; i++ {
		send(now.Add(time.Duration(i) * time.Minute))
	}
	if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_timer_observations WHERE machine_id=?`, machine).Scan(&n); e != nil || n != diskTimerHistoryLimit {
		t.Fatal("history not bounded", n, e)
	}
	if e := s.ReconcileDiskOwnership(now.Add(15 * 24 * time.Hour)); e != nil {
		t.Fatal(e)
	}
	if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_timer_observations WHERE machine_id=?`, machine).Scan(&n); e != nil || n != 1 {
		t.Fatal("retention failed to keep only latest stale receipt", n, e)
	}
	owner, e := s.DiskOwnershipGet(machine, "user")
	if e != nil || owner.Observation == nil || owner.Observation.ReceiptSequence == 0 {
		t.Fatal(owner, e)
	}
}

func TestDiskDeliveryStableKeyAndBudgets(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	reserve := func(key, lane string, at time.Time) int64 {
		t.Helper()
		id, e := s.ReserveDiskAlertDelivery(machine, key, lane, at)
		if e != nil {
			t.Fatal(e)
		}
		return id
	}
	id := reserve("critical-key", "critical", now)
	if id == 0 {
		t.Fatal("initial critical suppressed")
	}
	if e := s.FinishDiskAlertDelivery(id, true); e != nil {
		t.Fatal(e)
	}
	if reserve("critical-key", "critical", now.Add(6*time.Hour-time.Nanosecond)) != 0 {
		t.Fatal("flapping bypassed six-hour key throttle")
	}
	if reserve("critical-key", "critical", now.Add(6*time.Hour)) == 0 {
		t.Fatal("six-hour repeat suppressed")
	}
	id = reserve("warn-key", "warn", now)
	if id == 0 {
		t.Fatal("initial warning suppressed")
	}
	_ = s.FinishDiskAlertDelivery(id, true)
	if reserve("warn-key", "warn", now.Add(23*time.Hour)) != 0 {
		t.Fatal("warning flapping bypassed daily key throttle")
	}
	if reserve("warn-key", "warn", now.Add(24*time.Hour)) == 0 {
		t.Fatal("daily warning suppressed")
	}
	for i := 0; i < DiskAlertMachineHourlyBudget; i++ {
		reserve(fmt.Sprintf("many-%d", i), "critical", now.Add(48*time.Hour))
	}
	if reserve("beyond-machine", "critical", now.Add(48*time.Hour)) != 0 {
		t.Fatal("machine budget exceeded")
	}
	for m := 0; m < DiskAlertGlobalHourlyBudget/DiskAlertMachineHourlyBudget; m++ {
		other := mustEnroll(t, s, fmt.Sprintf("fixture-budget-%d", m), now)
		for i := 0; i < DiskAlertMachineHourlyBudget; i++ {
			if _, e := s.ReserveDiskAlertDelivery(other, fmt.Sprint(i), "critical", now.Add(72*time.Hour)); e != nil {
				t.Fatal(e)
			}
		}
	}
	if reserve("beyond-global", "critical", now.Add(72*time.Hour)) != 0 {
		t.Fatal("global budget exceeded")
	}
}

func TestDiskAckReplayAudited(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	v := 93
	_ = s.DiskAlertReading(req.Targets[0], "critical", "critical", &v, 93, now)
	alerts, _ := s.DiskAlertsList("")
	r := DiskAlertAckRequest{ID: alerts[0].ID, Reason: "capacity investigation"}
	p, e := s.DiskAlertAcknowledge(r, false, "", diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	r.ExpiresAt = p.ExpiresAt
	r.PreviewDigest = p.PreviewDigest
	for i := 0; i < 2; i++ {
		if _, e = s.DiskAlertAcknowledge(r, true, "ack-replay-audit", diskAdmin()); e != nil {
			t.Fatal(e)
		}
	}
	var n int
	if e = s.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='disk_alert_ack' AND idempotency_key='ack-replay-audit' AND detail='idempotent replay'`).Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	raw, _ := json.Marshal(r)
	if len(raw) == 0 {
		t.Fatal("missing request")
	}
}

func TestDiskRollbackWaitsForRunningAndVerifyingJobs(t *testing.T) {
	for _, state := range []deploy.JobState{deploy.Running, deploy.Verifying} {
		t.Run(string(state), func(t *testing.T) {
			s, req, now := safeDiskFixture(t)
			machine := req.Targets[0]
			p, e := s.ScriptRun(req, false, "", diskAdmin())
			if e != nil {
				t.Fatal(e)
			}
			req.PreviewDigest = p.PreviewDigest
			run, e := s.ScriptRun(req, true, "active-cleanup", diskAdmin())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.db.Exec(`UPDATE jobs SET state=? WHERE job_id=?`, state, run.JobIDs[0]); e != nil {
				t.Fatal(e)
			}
			owner, _ := s.DiskOwnershipGet(machine, "user")
			r := DiskOwnershipRequest{MachineID: machine, Scope: "user", Action: "rollback", Reason: "wait for active cleanup", ExpectedRevision: owner.Revision}
			preview, e := s.DiskOwnershipManage(r, false, "", diskAdmin())
			if e != nil {
				t.Fatal(e)
			}
			r.ExpiresAt = preview.ExpiresAt
			r.PreviewDigest = preview.PreviewDigest
			out, e := s.DiskOwnershipManage(r, true, "rollback-active", diskAdmin())
			if e != nil || out.Ownership.State != "rollback-pending" || out.Ownership.EnableCommand != "" {
				t.Fatal(out, e)
			}
			if e = s.ReconcileDiskOwnership(now.Add(time.Minute)); e != nil {
				t.Fatal(e)
			}
			owner, _ = s.DiskOwnershipGet(machine, "user")
			if owner.State != "rollback-pending" {
				t.Fatal(owner)
			}
			if e = s.FailJob(run.JobIDs[0], false, now.Add(2*time.Minute)); e != nil {
				t.Fatal(e)
			}
			if e = s.ReconcileDiskOwnership(now.Add(3 * time.Minute)); e != nil {
				t.Fatal(e)
			}
			owner, _ = s.DiskOwnershipGet(machine, "user")
			if owner.State != "local-owned" || owner.EnableCommand == "" {
				t.Fatal(owner)
			}
		})
	}
}

func TestDiskTimerSchemaMigrationKeepsLegacyLatestStale(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	if _, e := s.db.Exec(`DROP TABLE disk_timer_observations`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`CREATE TABLE disk_timer_observations(machine_id TEXT NOT NULL,scope TEXT NOT NULL,observed_at TEXT NOT NULL,body TEXT NOT NULL,PRIMARY KEY(machine_id,scope,observed_at))`); e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 20; i++ {
		o := model.DiskTimerObservation{Scope: "user", Known: true, ObservedAt: now.Add(time.Duration(i) * time.Minute)}
		raw, _ := json.Marshal(o)
		if _, e := s.db.Exec(`INSERT INTO disk_timer_observations VALUES (?,?,?,?)`, machine, "user", fmtTime(o.ObservedAt), string(raw)); e != nil {
			t.Fatal(e)
		}
	}
	if _, e := s.db.Exec(`DROP TABLE disk_ownership`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`CREATE TABLE disk_ownership(machine_id TEXT NOT NULL,scope TEXT NOT NULL,state TEXT CHECK(state IN ('local-owned','handoff-pending','hub-owned','rolled-back')),revision INTEGER NOT NULL,changed_at TEXT NOT NULL,PRIMARY KEY(machine_id,scope))`); e != nil {
		t.Fatal(e)
	}
	if _, e := s.db.Exec(`INSERT INTO disk_ownership VALUES (?,'user','handoff-pending',5,?)`, machine, fmtTime(now)); e != nil {
		t.Fatal(e)
	}
	if e := migrateDiskTimerEvidence(s.db); e != nil {
		t.Fatal(e)
	}
	if e := migrateDiskTimerEvidence(s.db); e != nil {
		t.Fatal("reopen migration", e)
	}
	var n int
	if e := s.rdb.QueryRow(`SELECT COUNT(*) FROM disk_timer_observations`).Scan(&n); e != nil || n != 1 {
		t.Fatal(n, e)
	}
	var nonce string
	if e := s.rdb.QueryRow(`SELECT transition_nonce FROM disk_ownership`).Scan(&nonce); e != nil || nonce == "" {
		t.Fatal("legacy pending transition has no new challenge", e)
	}
	owner, e := s.DiskOwnershipGet(machine, "user")
	if e != nil || owner.Observation.ReceivedAt.After(time.Unix(0, 0)) {
		t.Fatal("legacy evidence invented a fresh receipt", owner, e)
	}
	if _, e = s.db.Exec(`UPDATE disk_ownership SET state='rollback-pending'`); e != nil {
		t.Fatal("new state CHECK not migrated", e)
	}
}

func TestDiskHandoffEchoBeforeTransitionReceiptIsRejected(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	if _, e := s.db.Exec(`UPDATE disk_ownership SET state='handoff-pending',revision=8,transition_nonce='receipt-challenge',changed_at=? WHERE machine_id=? AND scope='user'`, diskReceiptTime(now.Add(time.Minute)), machine); e != nil {
		t.Fatal(e)
	}
	c := healthyCheckin(now)
	c.DiskOpsV2 = true
	c.DiskTimers = []model.DiskTimerObservation{{Scope: "user", Known: true, ObservedAt: now.Add(48 * time.Hour), TransitionRevision: 8, TransitionNonce: "receipt-challenge"}}
	if e := s.RecordCheckin(machine, c, now); e != nil {
		t.Fatal(e)
	}
	owner, _ := s.DiskOwnershipGet(machine, "user")
	if owner.State != "handoff-pending" {
		t.Fatal("receipt before transition admitted")
	}
}
