package store

import (
	"errors"
	"testing"
	"time"
)

func TestUsageFractionalReopen(t *testing.T) {
	for _, delta := range []time.Duration{100 * time.Millisecond, 100*time.Millisecond + time.Nanosecond, time.Nanosecond} {
		t.Run(delta.String(), func(t *testing.T) {
			s, machine, _ := usageFixture(t)
			now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			s.nowFn = func() time.Time { return now }
			p := DefaultUsagePolicy()
			digest, err := UsagePolicyPreviewDigest("fractional-policy", 0, p)
			if err != nil {
				t.Fatal(err)
			}
			policy, err := s.PublishUsagePolicy("fractional-policy", 0, p, digest, diskAdmin())
			if err != nil {
				t.Fatal(err)
			}
			r := UsageRecommendation{ID: "fractional-reopen", RuleID: "lower-effort", RuleVersion: 1, MachineID: machine, Scope: "machine", EvidenceDigest: digestOf("evidence"), EvidenceStart: now.Add(-time.Hour), EvidenceEnd: now, Confidence: "high", Proposer: "rule"}
			if err := s.CreateUsageRecommendation(r); err != nil {
				t.Fatal(err)
			}
			a, err := s.CreateOpsApproval(OpsApproval{ID: r.ID, MachineID: machine, Operation: "usage-recommendation-v1", PolicyID: policy.ID, PolicyRevision: policy.Revision, PolicyDigest: policy.Digest, ItemDigest: UsageRecommendationItemDigest(r)}, diskAdmin())
			if err != nil {
				t.Fatal(err)
			}
			reopen := now.Add(delta).In(time.FixedZone("offset", -5*3600))
			a, err = s.DecideUsageRecommendation(a, "snoozed", "later", &reopen, diskAdmin())
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.DecideUsageRecommendation(a, "snoozed", "later", &reopen, diskAdmin()); err != nil {
				t.Fatal(err)
			}
			records, err := s.UsageRecommendations(machine)
			if err != nil || len(records) != 1 || records[0].ReopenAt == nil || !records[0].ReopenAt.Equal(reopen) {
				t.Fatalf("records=%+v err=%v", records, err)
			}
			// Existing databases may contain timestamps with a non-UTC offset.
			if _, err := s.db.Exec(`UPDATE usage_recommendations SET reopen_at=? WHERE id=?`, reopen.Format(time.RFC3339Nano), r.ID); err != nil {
				t.Fatal(err)
			}
			for _, stamp := range []time.Time{now, reopen.Add(-time.Nanosecond)} {
				now = stamp
				if err := s.ReopenUsageRecommendation(r.ID, diskAdmin()); !errors.Is(err, ErrUsageConflict) {
					t.Fatalf("early reopen: %v", err)
				}
				if n := countRows(t, s, `SELECT count(*) FROM usage_recommendation_cycles`); n != 0 {
					t.Fatal("early cycle", n)
				}
			}
			now = reopen
			if err := s.ReopenUsageRecommendation(r.ID, diskAdmin()); err != nil {
				t.Fatal(err)
			}
			if err := s.ReopenUsageRecommendation(r.ID, diskAdmin()); !errors.Is(err, ErrUsageConflict) {
				t.Fatal(err)
			}
			holdings, err := s.MachineDataHoldings(machine)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, h := range holdings {
				if h.Table == "usage_recommendation_cycles" {
					found = true
					if h.Rows != 1 || h.Dated != 0 {
						t.Fatal(h)
					}
				}
			}
			if !found {
				t.Fatal("missing cycle holdings")
			}
			other := mustEnroll(t, s, "other", now)
			h, err := s.machineDataHolding(MachineDataTable{Table: "usage_recommendation_cycles"}, other)
			if err != nil || h.Rows != 0 {
				t.Fatal(h, err)
			}
		})
	}
}

func TestUsageRecommendationTimestampOrder(t *testing.T) {
	s, machine, _ := usageFixture(t)
	whole := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	// Seed historical fractional timestamps without weakening production immutability.
	if _, err := s.db.Exec(`DROP TRIGGER usage_recommendation_evidence_immutable`); err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"whole", "fraction"} {
		s.nowFn = func() time.Time { return whole }
		r := UsageRecommendation{ID: id, RuleID: "lower-effort", RuleVersion: 1, MachineID: machine, Scope: "machine", EvidenceDigest: digestOf(id), EvidenceStart: whole.Add(-time.Hour), EvidenceEnd: whole.Add(time.Nanosecond), Confidence: "high", Proposer: "rule"}
		if err := s.CreateUsageRecommendation(r); err != nil {
			t.Fatal(err)
		}
		if err := s.CreateUsageRecommendation(r); err != nil {
			t.Fatal("fractional evidence replay", err)
		}
		stamp := whole.Add(time.Duration(i) * 100 * time.Millisecond).Format(time.RFC3339Nano)
		if _, err := s.db.Exec(`UPDATE usage_recommendations SET created_at=? WHERE id=?`, stamp, id); err != nil {
			t.Fatal(err)
		}
	}
	records, err := s.UsageRecommendations(machine)
	if err != nil || len(records) != 2 || records[0].ID != "fraction" || records[1].ID != "whole" {
		t.Fatal(records, err)
	}
	h, err := s.machineDataHolding(MachineDataTable{Table: "usage_recommendations", TimeCol: "created_at"}, machine)
	if err != nil || h.Oldest == nil || h.Newest == nil || !h.Oldest.Equal(whole) || !h.Newest.Equal(whole.Add(100*time.Millisecond)) {
		t.Fatal(h, err)
	}
}

func TestUsageApprovalFractionalDeadlineFilter(t *testing.T) {
	s, machine, _ := usageFixture(t)
	whole := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return whole }
	p := DefaultUsagePolicy()
	digest, err := UsagePolicyPreviewDigest("fraction-policy", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := s.PublishUsagePolicy("fraction-policy", 0, p, digest, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	r := UsageRecommendation{ID: "fraction-approval", RuleID: "lower-effort", RuleVersion: 1, MachineID: machine, Scope: "machine", EvidenceDigest: digestOf("evidence"), EvidenceStart: whole.Add(-time.Hour), EvidenceEnd: whole, Confidence: "high", Proposer: "rule"}
	if err := s.CreateUsageRecommendation(r); err != nil {
		t.Fatal(err)
	}
	a, err := s.CreateOpsApproval(OpsApproval{ID: r.ID, MachineID: machine, Operation: "usage-recommendation-v1", PolicyID: policy.ID, PolicyRevision: policy.Revision, PolicyDigest: policy.Digest, ItemDigest: UsageRecommendationItemDigest(r)}, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce a persisted RFC3339Nano deadline from a legacy writer.
	if _, err := s.db.Exec(`DROP TRIGGER ops_approval_binding_immutable`); err != nil {
		t.Fatal(err)
	}
	deadline := whole.Add(100 * time.Millisecond)
	if _, err := s.db.Exec(`UPDATE ops_approvals SET deadline=?,created_at=? WHERE id=?`, deadline.Format(time.RFC3339Nano), whole.Add(-30*time.Minute).Format(time.RFC3339Nano), a.ID); err != nil {
		t.Fatal(err)
	}
	for _, stamp := range []time.Time{whole, deadline.Add(-time.Nanosecond), deadline, deadline.Add(time.Nanosecond)} {
		for _, state := range []string{"pending", "expired"} {
			rows, err := s.OpsApprovalsFiltered(state, machine, "usage-recommendation-v1", stamp)
			if err != nil {
				t.Fatal(err)
			}
			want := 0
			if (stamp.Before(deadline) && state == "pending") || (!stamp.Before(deadline) && state == "expired") {
				want = 1
			}
			if len(rows) != want {
				t.Fatalf("at %s filter %s: %d want %d", stamp, state, len(rows), want)
			}
		}
	}
}
