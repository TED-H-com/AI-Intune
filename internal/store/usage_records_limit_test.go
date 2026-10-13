package store

import (
	"fmt"
	"testing"
	"time"
)

func TestUsageSessionsAndJobsNewestBeforeLimit(t *testing.T) {
	s, machine, _ := usageFixture(t)
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return base.AddDate(0, 0, 303) }
	// Ascending identifiers deliberately oppose recency. Each pair ties in time/day.
	for i := 0; i < 606; i++ {
		id := fmt.Sprintf("%032x", i)
		end := base.Add(time.Duration(i/2) * time.Nanosecond)
		session := UsageSession{SessionHMAC: id, Tool: "codex", SourceType: "exec", Start: base, End: end}
		if err := s.UpsertUsageSession(machine, session); err != nil {
			t.Fatal(err)
		}
		day := base.AddDate(0, 0, i/2).Format("2006-01-02")
		// LastSeen opposes day ordering to ensure the day remains the primary key.
		job := UsageJob{Fingerprint: id, Day: day, Model: "gpt-5", Effort: "high", FirstSeen: base, LastSeen: base.Add(time.Duration(606-i) * time.Second)}
		if err := s.UpsertUsageJob(machine, job); err != nil {
			t.Fatal(err)
		}
	}
	for read := 0; read < 2; read++ {
		sessions, err := s.UsageSessions(machine)
		if err != nil {
			t.Fatal(err)
		}
		jobs, err := s.UsageJobs(machine)
		if err != nil {
			t.Fatal(err)
		}
		if len(sessions) != 500 || len(jobs) != 500 {
			t.Fatalf("lengths: sessions=%d jobs=%d", len(sessions), len(jobs))
		}
		for rank := 0; rank < 500; rank++ {
			index := 604 - (rank/2)*2 + rank%2
			want := fmt.Sprintf("%032x", index)
			if sessions[rank].SessionHMAC != want || jobs[rank].Fingerprint != want {
				t.Fatalf("rank %d: session=%s job=%s want=%s", rank, sessions[rank].SessionHMAC, jobs[rank].Fingerprint, want)
			}
		}
	}
}

func TestUsageRecommendationsActionableNewestBeforeLimit(t *testing.T) {
	for _, openCount := range []int{4, 504} {
		t.Run(fmt.Sprintf("open-%d", openCount), func(t *testing.T) {
			s, machine, _ := usageFixture(t)
			base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			if _, err := s.db.Exec(`DROP TRIGGER usage_recommendation_evidence_immutable`); err != nil {
				t.Fatal(err)
			}
			for i := 0; i < 606; i++ {
				created := base.Add(time.Duration(i/2) * time.Nanosecond)
				s.nowFn = func() time.Time { return created }
				id := fmt.Sprintf("recommendation-%04d", i)
				r := UsageRecommendation{ID: id, RuleID: "lower-effort", RuleVersion: 1, MachineID: machine, Scope: "machine", EvidenceDigest: digestOf(id), EvidenceStart: base.Add(-time.Hour), EvidenceEnd: base, Confidence: "high", Proposer: "rule"}
				if err := s.CreateUsageRecommendation(r); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec(`UPDATE usage_recommendations SET created_at=? WHERE id=?`, created.In(time.FixedZone("offset", 3600*(i%3))).Format(time.RFC3339Nano), id); err != nil {
					t.Fatal(err)
				}
				// Closed records are newer than every open record. Include all lifecycle states.
				if i >= openCount {
					state := []string{"approved", "dismissed", "snoozed", "expired", "superseded"}[i%5]
					if _, err := s.db.Exec(`UPDATE usage_recommendations SET state=? WHERE id=?`, state, id); err != nil {
						t.Fatal(err)
					}
				}
			}
			// Expected order is open first, then closed; newest pair first, ID ascending within pairs.
			var want []string
			for _, bounds := range [][2]int{{0, openCount}, {openCount, 606}} {
				for i := bounds[1] - 2; i >= bounds[0]; i -= 2 {
					want = append(want, fmt.Sprintf("recommendation-%04d", i), fmt.Sprintf("recommendation-%04d", i+1))
				}
			}
			for read := 0; read < 2; read++ {
				records, err := s.UsageRecommendations(machine)
				if err != nil {
					t.Fatal(err)
				}
				if len(records) != 500 {
					t.Fatalf("got %d records", len(records))
				}
				for rank, record := range records {
					if record.ID != want[rank] {
						t.Fatalf("rank %d: got %s want %s", rank, record.ID, want[rank])
					}
					if rank < openCount && record.State != "open" {
						t.Fatalf("rank %d: state=%s", rank, record.State)
					}
				}
			}
		})
	}
}
