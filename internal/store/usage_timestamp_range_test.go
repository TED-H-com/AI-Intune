package store

import (
	"errors"
	"testing"
	"time"
)

func TestUsageTimestampRange(t *testing.T) {
	min := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	max := time.Date(2200, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		stamp, now time.Time
		valid      bool
	}{
		{min, time.Time{}, true}, {max, time.Time{}, true},
		{min.Add(-time.Nanosecond), time.Time{}, false},
		{max.Add(time.Nanosecond), time.Time{}, false},
		{time.Time{}, now, false}, {now.Add(5 * time.Minute), now, true},
		{now.Add(5*time.Minute + time.Nanosecond), now, false},
		{now.In(time.FixedZone("offset", -5*3600)), now, true},
	} {
		if err := validateUsageTimestamp(tc.stamp, tc.now); (err == nil) != tc.valid {
			t.Fatalf("stamp %s now %s: %v", tc.stamp, tc.now, err)
		}
	}
}

func TestUsageRejectsPoisonedSnapshotTimestamps(t *testing.T) {
	s, machine, in := usageFixture(t)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	s.nowFn = func() time.Time { return now }
	account := UsageAccount{AccountID: usageTestHash, MachineID: machine, Provider: "openai", Plan: "pro", DiscoverySource: "status", LastSeen: now}
	session := UsageSession{SessionHMAC: usageTestHash, Tool: "codex", SourceType: "exec", Start: now, End: now}
	job := UsageJob{Fingerprint: usageTestHash, Day: "2026-10-13", Model: "gpt-5", Effort: "high", FirstSeen: now, LastSeen: now}
	for _, err := range []error{s.UpsertUsageAccount(account), s.UpsertUsageSession(machine, session), s.UpsertUsageJob(machine, job)} {
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, stamp := range []time.Time{
		time.Date(1600, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2500, 1, 1, 0, 0, 0, 0, time.UTC),
		now.Add(5*time.Minute + time.Nanosecond),
	} {
		a, b, c := account, session, job
		a.LastSeen = stamp
		b.Start, b.End = stamp, stamp
		c.FirstSeen, c.LastSeen = stamp, stamp
		for name, err := range map[string]error{"account": s.UpsertUsageAccount(a), "session": s.UpsertUsageSession(machine, b), "job": s.UpsertUsageJob(machine, c)} {
			if !errors.Is(err, ErrUsageInvalid) {
				t.Fatalf("%s at %s: %v", name, stamp, err)
			}
		}
	}
	accounts, err := s.UsageAccounts()
	if err != nil || len(accounts) != 1 || !accounts[0].LastSeen.Equal(now) {
		t.Fatal(accounts, err)
	}
	sessions, err := s.UsageSessions(machine)
	if err != nil || len(sessions) != 1 || !sessions[0].End.Equal(now) {
		t.Fatal(sessions, err)
	}
	jobs, err := s.UsageJobs(machine)
	if err != nil || len(jobs) != 1 || !jobs[0].LastSeen.Equal(now) {
		t.Fatal(jobs, err)
	}
	for _, window := range []bool{false, true} {
		for _, period := range []string{"1600-01-01", "2500-01-01", "2027-01-01"} {
			row := in.Daily[0]
			row.Period = period
			snapshot := in
			snapshot.Daily, snapshot.Window = nil, nil
			if window {
				row.Period += "T00:00:00Z"
				snapshot.Window = []UsageAggregate{row}
			} else {
				snapshot.Daily = []UsageAggregate{row}
			}
			if _, err := s.MergeUsageFile(machine, snapshot); !errors.Is(err, ErrUsageInvalid) {
				t.Fatalf("period %s: %v", row.Period, err)
			}
		}
	}
}

func TestUsageRejectsOutOfRangeReopen(t *testing.T) {
	s, _, _ := usageFixture(t)
	for _, year := range []int{1600, 2500} {
		stamp := time.Date(year, 1, 1, 0, 0, 0, 0, time.UTC)
		_, err := s.DecideUsageRecommendation(OpsApproval{Operation: "usage-recommendation-v1"}, "snoozed", "later", &stamp, diskAdmin())
		if !errors.Is(err, ErrUsageInvalid) {
			t.Fatalf("year %d: %v", year, err)
		}
	}
}

func TestUsageMigrationRejectsPoisonedTimestamp(t *testing.T) {
	for _, table := range []string{"usage_accounts", "usage_sessions", "usage_jobs"} {
		t.Run(table, func(t *testing.T) {
			s, machine, _ := usageFixture(t)
			stamp := s.now()
			var err error
			var column string
			switch table {
			case "usage_accounts":
				err = s.UpsertUsageAccount(UsageAccount{AccountID: usageTestHash, MachineID: machine, Provider: "openai", Plan: "pro", DiscoverySource: "status", LastSeen: stamp})
				column = "last_seen_ns"
			case "usage_sessions":
				err = s.UpsertUsageSession(machine, UsageSession{SessionHMAC: usageTestHash, Tool: "codex", SourceType: "exec", Start: stamp, End: stamp})
				column = "end_ns"
			case "usage_jobs":
				err = s.UpsertUsageJob(machine, UsageJob{Fingerprint: usageTestHash, Day: stamp.UTC().Format("2006-01-02"), Model: "gpt-5", Effort: "high", FirstSeen: stamp, LastSeen: stamp})
				column = "last_seen_ns"
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = s.db.Exec("ALTER TABLE " + table + " DROP COLUMN " + column); err != nil {
				t.Fatal(err)
			}
			query := "UPDATE " + table + " SET last_seen='2500-01-01T00:00:00Z'"
			if table == "usage_sessions" {
				query = "UPDATE " + table + " SET body=json_set(body, '$.End', '2500-01-01T00:00:00Z')"
			}
			if table == "usage_jobs" {
				query = "UPDATE " + table + " SET body=json_set(body, '$.LastSeen', '2500-01-01T00:00:00Z')"
			}
			if _, err = s.db.Exec(query); err != nil {
				t.Fatal(err)
			}
			if err = migrateUsageSnapshotTimes(s.db); !errors.Is(err, ErrUsageInvalid) {
				t.Fatalf("migration: %v", err)
			}
		})
	}
}
