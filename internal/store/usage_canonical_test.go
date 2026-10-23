package store

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"
)

func TestUsageSnapshotCanonicalReplay(t *testing.T) {
	s, m, in := usageFixture(t)
	second := in.Daily[0]
	second.Model = "gpt-5.2"
	in.Daily = append(in.Daily, second)
	in.Window = append([]UsageAggregate{}, in.Daily...)
	for i := range in.Window {
		in.Window[i].Period = "2026-10-13T12:00:00Z"
	}
	if _, err := s.MergeUsageFile(m, in); err != nil {
		t.Fatal(err)
	}
	replay := in
	replay.Daily = []UsageAggregate{in.Daily[1], in.Daily[0]}
	replay.Window = []UsageAggregate{in.Window[1], in.Window[0]}
	replay.Daily[0].Metrics.EstCostUSD = math.Copysign(0, -1)
	replay.Window[0].Metrics.ToolCalls = map[string]int64{}
	if changed, err := s.MergeUsageFile(m, replay); err != nil || changed {
		t.Fatal(changed, err)
	}
	if in.Daily[0].Model != "gpt-5-codex" {
		t.Fatal("mutated caller ordering")
	}
	replay.Daily[0].Metrics.Calls++
	if _, err := s.MergeUsageFile(m, replay); !errors.Is(err, ErrUsageConflict) {
		t.Fatal(err)
	}
}

func TestUsageRecordCanonicalReplay(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "new", true: "legacy"}[legacy], func(t *testing.T) {
			s, m, _ := usageFixture(t)
			start := time.Date(2026, 10, 13, 12, 0, 0, 123, time.FixedZone("offset", -4*3600))
			s.nowFn = func() time.Time { return start.Add(time.Hour) }
			session := UsageSession{SessionHMAC: usageTestHash, Tool: "codex", SourceType: "exec", Start: start, End: start.Add(time.Hour), Models: []string{"gpt-5.2", "gpt-5"}, Efforts: []string{"high", "low"}}
			job := UsageJob{Fingerprint: usageTestHash, Day: "2026-10-13", Model: "gpt-5", Effort: "high", FirstSeen: start, LastSeen: session.End}
			if err := s.UpsertUsageSession(m, session); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertUsageJob(m, job); err != nil {
				t.Fatal(err)
			}
			if legacy {
				if _, err := s.db.Exec("UPDATE usage_sessions SET body=?", string(mustScriptJSON(session))); err != nil {
					t.Fatal(err)
				}
				if _, err := s.db.Exec("UPDATE usage_jobs SET body=?", string(mustScriptJSON(job))); err != nil {
					t.Fatal(err)
				}
			} else {
				var raw string
				if err := s.rdb.QueryRow("SELECT body FROM usage_sessions").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var stored UsageSession
				if err := json.Unmarshal([]byte(raw), &stored); err != nil {
					t.Fatal(err)
				}
				if stored.Start.Location() != time.UTC || stored.End.Location() != time.UTC {
					t.Fatal(raw)
				}
				if err := s.rdb.QueryRow("SELECT body FROM usage_jobs").Scan(&raw); err != nil {
					t.Fatal(err)
				}
				var storedJob UsageJob
				if err := json.Unmarshal([]byte(raw), &storedJob); err != nil {
					t.Fatal(err)
				}
				if storedJob.FirstSeen.Location() != time.UTC || storedJob.LastSeen.Location() != time.UTC {
					t.Fatal(raw)
				}
			}
			session.Start, session.End = session.Start.UTC(), session.End.UTC()
			session.Models = []string{"gpt-5", "gpt-5.2"}
			session.Efforts = []string{"low", "high"}
			session.Metrics.EstCostUnits = math.Copysign(0, -1)
			job.FirstSeen, job.LastSeen = job.FirstSeen.UTC(), job.LastSeen.UTC()
			job.TokensPerRun.EstCostUSD = math.Copysign(0, -1)
			if err := s.UpsertUsageSession(m, session); err != nil {
				t.Fatal(err)
			}
			if err := s.UpsertUsageJob(m, job); err != nil {
				t.Fatal(err)
			}
			session.Metrics.Calls++
			job.Runs++
			if err := s.UpsertUsageSession(m, session); !errors.Is(err, ErrUsageConflict) {
				t.Fatal(err)
			}
			if err := s.UpsertUsageJob(m, job); !errors.Is(err, ErrUsageConflict) {
				t.Fatal(err)
			}
		})
	}
}

func TestUsageReopenRequiresAdminAndAtomicAudit(t *testing.T) {
	s, m, _ := usageFixture(t)
	now := s.now()
	r := UsageRecommendation{ID: "reopen-auth", RuleID: "rule", RuleVersion: 1, MachineID: m, Scope: "machine", EvidenceDigest: digestOf("evidence"), EvidenceStart: now.Add(-time.Hour), EvidenceEnd: now, Confidence: "high", Proposer: "rule"}
	if err := s.CreateUsageRecommendation(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE usage_recommendations SET state='snoozed',reopen_at=? WHERE id=?", now.Add(-time.Hour).UTC().Format(time.RFC3339Nano), r.ID); err != nil {
		t.Fatal(err)
	}
	for _, actor := range []AuditEntry{{}, func() AuditEntry { a := diskAdmin(); a.AuthCapability = "viewer"; return a }(), func() AuditEntry { a := diskAdmin(); a.AuthMethod = "agent"; return a }()} {
		if err := s.ReopenUsageRecommendation(r.ID, actor); err == nil {
			t.Fatal("unauthorized reopen")
		}
	}
	if n := countRows(t, s, "SELECT COUNT(*) FROM usage_recommendation_cycles"); n != 0 {
		t.Fatal(n)
	}
	if _, err := s.db.Exec("CREATE TRIGGER reject_reopen_audit BEFORE INSERT ON audit_log WHEN NEW.detail='usage recommendation reopened' BEGIN SELECT RAISE(ABORT,'audit failure'); END"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReopenUsageRecommendation(r.ID, diskAdmin()); err == nil {
		t.Fatal("missing audit accepted")
	}
	if n := countRows(t, s, "SELECT COUNT(*) FROM usage_recommendation_cycles"); n != 0 {
		t.Fatal("cycle escaped rollback", n)
	}
	if _, err := s.db.Exec("DROP TRIGGER reject_reopen_audit"); err != nil {
		t.Fatal(err)
	}
	if err := s.ReopenUsageRecommendation(r.ID, diskAdmin()); err != nil {
		t.Fatal(err)
	}
	if n := countRows(t, s, "SELECT COUNT(*) FROM audit_log WHERE detail='usage recommendation reopened' AND outcome='ok'"); n != 1 {
		t.Fatal(n)
	}
}
