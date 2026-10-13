package store

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestUsageSnapshotTimestampOrdering(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		name := "fresh"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "usage.db")
			s, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { s.Close() }()
			machine := mustEnroll(t, s, "timestamp-test", s.now())
			whole := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
			account := UsageAccount{AccountID: usageTestHash, MachineID: machine, Provider: "openai", Plan: "pro", DiscoverySource: "status", LastSeen: whole}
			session := UsageSession{SessionHMAC: usageTestHash, Tool: "codex", SourceType: "exec", Start: whole, End: whole}
			job := UsageJob{Fingerprint: usageTestHash, Day: "2026-10-13", Model: "gpt-5", Effort: "high", FirstSeen: whole, LastSeen: whole}
			write := func() {
				t.Helper()
				for name, err := range map[string]error{"account": s.UpsertUsageAccount(account.MachineID, account), "session": s.UpsertUsageSession(machine, session), "job": s.UpsertUsageJob(machine, job)} {
					if err != nil {
						t.Fatalf("%s: %v", name, err)
					}
				}
			}
			check := func(stamp time.Time, count int64, plan string) {
				t.Helper()
				accounts, err := s.UsageAccounts()
				if err != nil || len(accounts) != 1 || !accounts[0].LastSeen.Equal(stamp) || accounts[0].Plan != plan {
					t.Fatalf("accounts: %+v, %v", accounts, err)
				}
				sessions, err := s.UsageSessions(machine)
				if err != nil || len(sessions) != 1 || !sessions[0].End.Equal(stamp) || sessions[0].Metrics.Calls != count {
					t.Fatalf("sessions: %+v, %v", sessions, err)
				}
				jobs, err := s.UsageJobs(machine)
				if err != nil || len(jobs) != 1 || !jobs[0].LastSeen.Equal(stamp) || jobs[0].Runs != count {
					t.Fatalf("jobs: %+v, %v", jobs, err)
				}
				for _, spec := range []struct{ table, column string }{{"usage_accounts", "last_seen_ns"}, {"usage_sessions", "end_ns"}, {"usage_jobs", "last_seen_ns"}} {
					var ns int64
					if err := s.rdb.QueryRow("SELECT " + spec.column + " FROM " + spec.table).Scan(&ns); err != nil || ns != stamp.UnixNano() {
						t.Fatalf("%s ns=%d want=%d: %v", spec.table, ns, stamp.UnixNano(), err)
					}
				}
			}
			write()
			if legacy {
				// Strip the new columns to reproduce the previous schema with real rows.
				if _, err := s.db.Exec(`ALTER TABLE usage_accounts DROP COLUMN last_seen_ns;
ALTER TABLE usage_sessions DROP COLUMN end_ns;
ALTER TABLE usage_jobs DROP COLUMN last_seen_ns`); err != nil {
					t.Fatal(err)
				}
				s.Close()
				s, err = Open(path)
				if err != nil {
					t.Fatal(err)
				}
				check(whole, 0, "pro")
			}
			// Variable-width fractions, nanosecond precision, and offsets must all
			// order by instant. Each older write follows its newer replacement.
			for i, delta := range []time.Duration{100 * time.Millisecond, 100*time.Millisecond + time.Nanosecond, time.Second, time.Second + time.Nanosecond} {
				previousAccount, previousSession, previousJob := account, session, job
				stamp := whole.Add(delta)
				account.LastSeen = stamp.In(time.FixedZone("offset", -5*60*60))
				account.Plan = []string{"free", "plus", "max", "team"}[i]
				session.End = account.LastSeen
				session.Metrics.Calls = int64(i + 1)
				job.LastSeen = account.LastSeen
				job.Runs = int64(i + 1)
				write()
				check(stamp, int64(i+1), account.Plan)
				newerAccount, newerSession, newerJob := account, session, job
				account, session, job = previousAccount, previousSession, previousJob
				write()
				check(stamp, int64(i+1), newerAccount.Plan)
				account, session, job = newerAccount, newerSession, newerJob
				write() // Exact replay remains harmless.
				account.Plan = "other"
				session.Metrics.Calls++
				job.Runs++
				for name, err := range map[string]error{"account": s.UpsertUsageAccount(account.MachineID, account), "session": s.UpsertUsageSession(machine, session), "job": s.UpsertUsageJob(machine, job)} {
					if !errors.Is(err, ErrUsageConflict) {
						t.Fatalf("%s equal timestamp: %v", name, err)
					}
				}
				account, session, job = newerAccount, newerSession, newerJob
			}
			// Reopening also verifies migration idempotence and persisted fractions.
			if legacy {
				if _, err := s.db.Exec(`ALTER TABLE usage_accounts DROP COLUMN last_seen_ns;
ALTER TABLE usage_sessions DROP COLUMN end_ns;
ALTER TABLE usage_jobs DROP COLUMN last_seen_ns`); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			for i := 0; i < 2; i++ {
				s, err = Open(path)
				if err != nil {
					t.Fatal(err)
				}
				check(account.LastSeen, job.Runs, account.Plan)
				s.Close()
			}
		})
	}
}
