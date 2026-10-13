package store

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const usageTestHash = "0123456789abcdef0123456789abcdef"

func usageFixture(t *testing.T) (*Store, string, UsageFileSnapshot) {
	t.Helper()
	s := newTestStore(t)
	machine := mustEnroll(t, s, "usage-test", s.now())
	a := UsageAggregate{Tool: "codex",
		AccountID:    "unknown",
		Model:        "gpt-5-codex",
		Effort:       "unknown",
		EffortSource: "unknown",
		SourceType:   "exec",
		Period:       "2026-10-13",
		Metrics: UsageMetrics{Calls: 1,
			InputUncached: 100,
			CounterResets: 1}}
	return s, machine, UsageFileSnapshot{FileHMAC: usageTestHash, OffsetTo: 100, Daily: []UsageAggregate{a}}
}
func TestUsageSnapshotReplayAppendRewrite(t *testing.T) {
	s, m, in := usageFixture(t)
	if changed, e := s.MergeUsageFile(m, in); e != nil || !changed {
		t.Fatal(changed, e)
	}
	if changed, e := s.MergeUsageFile(m, in); e != nil || changed {
		t.Fatal(changed, e)
	}
	next := in
	next.Daily = append([]UsageAggregate(nil), in.Daily...)
	next.OffsetFrom = 100
	next.OffsetTo = 200
	next.Daily[0].Metrics.InputUncached = 120
	next.Daily[0].Metrics.CounterResets = 2
	if _, e := s.MergeUsageFile(m, next); e != nil {
		t.Fatal(e)
	}
	if changed, e := s.MergeUsageFile(m, in); e != nil || changed {
		t.Fatal("old replay", changed, e)
	}
	rows, e := s.UsageContributions(m, false)
	if e != nil || len(rows) != 1 || rows[0].Metrics.InputUncached != 120 || rows[0].Metrics.CacheWrite != nil || rows[0].Metrics.CounterResets != 2 {
		t.Fatal(rows, e)
	}
	next.Generation = 1
	next.OffsetFrom = 0
	next.OffsetTo = 50
	next.Daily[0].Metrics.InputUncached = 20
	if _, e = s.MergeUsageFile(m, next); e != nil {
		t.Fatal(e)
	}
	rows, _ = s.UsageContributions(m, false)
	if len(rows) != 1 || rows[0].Metrics.InputUncached != 20 {
		t.Fatal("rewrite doubled", rows)
	}
	bad := next
	bad.OffsetTo = 60
	bad.OffsetFrom = 30
	if _, e = s.MergeUsageFile(m, bad); !errors.Is(e, ErrUsageConflict) {
		t.Fatal(e)
	}
}
func TestUsageSnapshotAtomicValidationIsolation(t *testing.T) {
	s, m, in := usageFixture(t)
	other := mustEnroll(t, s, "usage-other", s.now())
	bad := in
	bad.Daily = append([]UsageAggregate(nil), in.Daily...)
	bad.Daily[0].Model = "/private/project"
	if _, e := s.MergeUsageFile(m, bad); e == nil {
		t.Fatal("accepted raw model")
	}
	if _, e := s.MergeUsageFile("missing", in); e == nil {
		t.Fatal("accepted unknown machine")
	}
	in.Daily = append(in.Daily, in.Daily[0])
	if _, e := s.MergeUsageFile(m, in); e == nil {
		t.Fatal("accepted duplicate key")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM usage_files`); n != 0 {
		t.Fatal("partial merge", n)
	}
	in.Daily = in.Daily[:1]
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := s.MergeUsageFile(m, in); e != nil {
				t.Error(e)
			}
		}()
	}
	wg.Wait()
	if _, e := s.MergeUsageFile(other, in); e != nil {
		t.Fatal(e)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM usage_daily`); n != 2 {
		t.Fatal(n)
	}
	zero := int64(0)
	in.OffsetFrom = 100
	in.OffsetTo = 110
	in.Daily[0].Metrics.CacheWrite = &zero
	if _, e := s.MergeUsageFile(m, in); e != nil {
		t.Fatal(e)
	}
	rows, _ := s.UsageContributions(m, false)
	if rows[0].Metrics.CacheWrite == nil || *rows[0].Metrics.CacheWrite != 0 {
		t.Fatal("lost known zero")
	}
}
func TestUsageRecordsPrivacyAndIdempotence(t *testing.T) {
	s, m, _ := usageFixture(t)
	now := s.now().UTC()
	a := UsageAccount{AccountID: usageTestHash, MachineID: m, Provider: "openai", Plan: "pro", DiscoverySource: "status", LastSeen: now}
	for i := 0; i < 2; i++ {
		if e := s.UpsertUsageAccount(a); e != nil {
			t.Fatal(e)
		}
	}
	a.LastSeen = now.Add(-time.Hour)
	a.Plan = "free"
	if e := s.UpsertUsageAccount(a); e != nil {
		t.Fatal(e)
	}
	accounts, e := s.UsageAccounts()
	if e != nil || len(accounts) != 1 || accounts[0].Plan != "pro" {
		t.Fatal(accounts, e)
	}
	a.AccountID = "person@example.invalid"
	if e = s.UpsertUsageAccount(a); e == nil {
		t.Fatal("accepted identity")
	}
	session := UsageSession{SessionHMAC: usageTestHash,
		Tool:       "codex",
		SourceType: "exec",
		Start:      now,
		End:        now,
		Models:     []string{"gpt-5"},
		Efforts:    []string{"high"}}
	job := UsageJob{Fingerprint: usageTestHash, Day: "2026-10-13", Model: "gpt-5", Effort: "high", Runs: 2, FirstSeen: now, LastSeen: now}
	for i := 0; i < 2; i++ {
		if e = s.UpsertUsageSession(m, session); e != nil {
			t.Fatal(e)
		}
		if e = s.UpsertUsageJob(m, job); e != nil {
			t.Fatal(e)
		}
	}
	sessions, e := s.UsageSessions(m)
	if e != nil || len(sessions) != 1 {
		t.Fatal(sessions, e)
	}
	jobs, e := s.UsageJobs(m)
	if e != nil || len(jobs) != 1 || jobs[0].Runs != 2 {
		t.Fatal(jobs, e)
	}
	session.ProjectHMAC = "/private/path"
	if e = s.UpsertUsageSession(m, session); e == nil {
		t.Fatal("accepted path")
	}
}
func TestUsagePolicyAndAdviceLedger(t *testing.T) {
	s, m, _ := usageFixture(t)
	p := DefaultUsagePolicy()
	if p.Enabled || p.CrossMachineJobs || !p.TaskLabels || p.LabelMaxChars != 40 || p.BackfillDays != 90 {
		t.Fatal(p)
	}
	preview, e := UsagePolicyPreviewDigest("usage-default", 0, p)
	if e != nil {
		t.Fatal(e)
	}
	policy, e := s.PublishUsagePolicy("usage-default", 0, p, preview, diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	replay, e := s.PublishUsagePolicy("usage-default", 0, p, preview, diskAdmin())
	if e != nil || replay.Revision != 1 {
		t.Fatal(replay, e)
	}
	p.LabelMaxChars = 41
	if _, e = UsagePolicyPreviewDigest("usage-default", 1, p); e == nil {
		t.Fatal("unbounded labels")
	}
	p = DefaultUsagePolicy()
	denied := diskAdmin()
	denied.AuthMethod = "service-token"
	if _, e = s.PublishUsagePolicy("usage-default", 0, p, preview, denied); e == nil {
		t.Fatal("agent published")
	}
	now := s.now().UTC()
	r := UsageRecommendation{ID: "recommendation-one",
		RuleID:         "lower-effort",
		RuleVersion:    1,
		MachineID:      m,
		Scope:          "machine",
		EvidenceDigest: digestOf("numeric evidence"),
		EvidenceStart:  now.Add(-24 * time.Hour),
		EvidenceEnd:    now,
		Confidence:     "high",
		Proposer:       "rule"}
	if e = s.CreateUsageRecommendation(r); e != nil {
		t.Fatal(e)
	}
	if e = s.CreateUsageRecommendation(r); e != nil {
		t.Fatal(e)
	}
	binding := OpsApproval{ID: r.ID,
		MachineID:      m,
		Operation:      "usage-recommendation-v1",
		PolicyID:       policy.ID,
		PolicyRevision: policy.Revision,
		PolicyDigest:   policy.Digest,
		ItemDigest:     UsageRecommendationItemDigest(r)}
	a, e := s.CreateOpsApproval(binding, diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	reopen := now.Add(24 * time.Hour)
	a, e = s.DecideUsageRecommendation(a, "snoozed", "review later", &reopen, diskAdmin())
	if e != nil || a.State != "rejected" || !strings.HasPrefix(a.DecisionReason, "snooze:") {
		t.Fatal(a, e)
	}
	if _, e = s.DecideUsageRecommendation(a, "snoozed", "review later", &reopen, diskAdmin()); e != nil {
		t.Fatal(e)
	}
	var state, at string
	if e = s.rdb.QueryRow(`SELECT state,reopen_at FROM usage_recommendations WHERE id=?`,
		r.ID).Scan(&state,
		&at); e != nil || state != "snoozed" || at != fmtTime(reopen) {
		t.Fatal(state, at, e)
	}
	if _, e = s.OpsApprovalsFiltered("rejected", "", "usage-recommendation-v1", now); e != nil {
		t.Fatal(e)
	}
	if _, e = s.DecideOpsApproval(a, true, diskAdmin()); e == nil {
		t.Fatal("disk adapter accepted advice")
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM jobs`); n != 0 {
		t.Fatal("advice dispatched job", n)
	}
}
func TestUsageLegacyMigrationAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	// Reconstruct a legacy disk-only parent with an existing immutable revision.
	_, e = s.db.Exec(`DROP TRIGGER ops_policy_no_delete;
DROP TRIGGER ops_policy_immutable;
DROP INDEX ops_policy_current;
DROP TABLE ops_policies;
CREATE TABLE ops_policies(id TEXT NOT NULL, kind TEXT NOT NULL
CHECK(kind='disk'), revision INTEGER NOT NULL CHECK(revision>0), body TEXT NOT NULL, digest TEXT NOT
NULL, created_by TEXT NOT NULL, created_at TEXT NOT NULL, superseded_at TEXT, PRIMARY KEY(id,
revision));
INSERT INTO ops_policies VALUES ('legacy', 'disk', 1, '{}', 'digest', 'human',
'2026-10-13T00:00:00Z', NULL)`)
	if e != nil {
		t.Fatal(e)
	}
	s.Close()
	for i := 0; i < 2; i++ {
		s, e = Open(path)
		if e != nil {
			t.Fatal(e)
		}
		if n := countRows(t, s, `SELECT COUNT(*) FROM ops_policies WHERE id='legacy' AND kind='disk'`); n != 1 {
			t.Fatal(n)
		}
		if _, e = s.db.Exec(`UPDATE ops_policies SET body='changed' WHERE id='legacy'`); e == nil {
			t.Fatal("lost immutable trigger")
		}
		for _, table := range []string{"usage_accounts", "usage_daily", "usage_window", "usage_sessions", "usage_jobs", "usage_recommendations"} {
			if n := countRows(t, s, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table); n != 1 {
				t.Fatal(table)
			}
		}
		s.Close()
	}
}

func TestUsageMetricsAndWindowValidation(t *testing.T) {
	s, m, in := usageFixture(t)
	window := in.Daily[0]
	window.Period = "2026-10-13T12:00:00Z"
	in.Window = []UsageAggregate{window}
	if _, e := s.MergeUsageFile(m, in); e != nil {
		t.Fatal(e)
	}
	rows, e := s.UsageContributions(m, true)
	if e != nil || len(rows) != 1 || rows[0].Metrics.InputUncached != 100 {
		t.Fatal(rows, e)
	}
	negative := int64(-1)
	for _, mutate := range []func(*UsageAggregate){func(a *UsageAggregate) { a.Metrics.Calls = -1 },
		func(a *UsageAggregate) { a.Metrics.CacheWrite = &negative },
		func(a *UsageAggregate) { a.Metrics.GapHistogram[1] = -1 },
		func(a *UsageAggregate) { a.Metrics.ToolCalls = map[string]int64{"/private/argument": 1} },
		func(a *UsageAggregate) { a.Metrics.InputUncached = 1 << 54 },
		func(a *UsageAggregate) { a.AccountID = "raw-account" },
		func(a *UsageAggregate) { a.EffortSource = "guessed" },
		func(a *UsageAggregate) { a.Period = "2026-02-30" }} {
		a := in.Daily[0]
		mutate(&a)
		if e = a.validate(false); e == nil {
			t.Fatal("invalid aggregate accepted")
		}
	}
}
func TestUsagePolicyConflictAndAuditRollback(t *testing.T) {
	s := newTestStore(t)
	p := DefaultUsagePolicy()
	preview, _ := UsagePolicyPreviewDigest("usage", 0, p)
	policy, e := s.PublishUsagePolicy("usage", 0, p, preview, diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	p.ReadBytesPerSecond++
	bad, _ := UsagePolicyPreviewDigest("usage", 0, p)
	if _, e = s.PublishUsagePolicy("usage", 0, p, bad, diskAdmin()); !errors.Is(e, ErrUsageConflict) {
		t.Fatal(e)
	}
	preview, _ = UsagePolicyPreviewDigest("usage", 1, p)
	policy, e = s.PublishUsagePolicy("usage", 1, p, preview, diskAdmin())
	if e != nil || policy.Revision != 2 {
		t.Fatal(policy, e)
	}
	if n := countRows(t, s, `SELECT COUNT(*) FROM ops_policies WHERE id='usage' AND superseded_at IS NULL`); n != 1 {
		t.Fatal(n)
	}
	if _, e = s.db.Exec(`CREATE TRIGGER usage_audit_fail BEFORE INSERT ON audit_log BEGIN SELECT RAISE(ABORT,'audit unavailable');END`); e != nil {
		t.Fatal(e)
	}
	p.ReadBytesPerSecond++
	preview, _ = UsagePolicyPreviewDigest("usage", 2, p)
	if _, e = s.PublishUsagePolicy("usage", 2, p, preview, diskAdmin()); e == nil {
		t.Fatal("publication survived missing audit")
	}
	current, e := s.UsagePolicy("usage")
	if e != nil || current.Revision != 2 {
		t.Fatal(current, e)
	}
}

func TestUsageDecisionsAndBindingDenials(t *testing.T) {
	for _, decision := range []string{"approved", "dismissed"} {
		t.Run(decision, func(t *testing.T) {
			s, m, _ := usageFixture(t)
			now := s.now().UTC()
			p := DefaultUsagePolicy()
			preview, _ := UsagePolicyPreviewDigest("usage", 0, p)
			policy, e := s.PublishUsagePolicy("usage", 0, p, preview, diskAdmin())
			if e != nil {
				t.Fatal(e)
			}
			r := UsageRecommendation{ID: "advice",
				RuleID:         "quota-pacing",
				MachineID:      m,
				RuleVersion:    1,
				Scope:          "account",
				ScopeHMAC:      usageTestHash,
				EvidenceDigest: digestOf("evidence"),
				EvidenceStart:  now.Add(-time.Hour),
				EvidenceEnd:    now,
				Confidence:     "low",
				Proposer:       "rule"}
			if e = s.CreateUsageRecommendation(r); e != nil {
				t.Fatal(e)
			}
			binding := OpsApproval{ID: r.ID,
				MachineID:      m,
				Operation:      "usage-recommendation-v1",
				PolicyID:       policy.ID,
				PolicyRevision: policy.Revision,
				PolicyDigest:   policy.Digest,
				ItemDigest:     UsageRecommendationItemDigest(r)}
			bad := binding
			bad.ItemDigest = digestOf("changed")
			if _, e = s.CreateOpsApproval(bad, diskAdmin()); e == nil {
				t.Fatal("unbound evidence accepted")
			}
			a, e := s.CreateOpsApproval(binding, diskAdmin())
			if e != nil {
				t.Fatal(e)
			}
			if _, e = s.CreateOpsApproval(binding, diskAdmin()); e != nil {
				t.Fatal("approval replay", e)
			}
			agent := diskAdmin()
			agent.AuthMethod = "service-token"
			if _, e = s.DecideUsageRecommendation(a, decision, "reviewed evidence", nil, agent); e == nil {
				t.Fatal("agent decided")
			}
			wrong := a
			wrong.ItemDigest = digestOf("changed")
			if _, e = s.DecideUsageRecommendation(wrong, decision, "reviewed evidence", nil, diskAdmin()); e == nil {
				t.Fatal("changed binding accepted")
			}
			if _, e = s.DecideUsageRecommendation(a, decision, "snooze:fake", nil, diskAdmin()); e == nil {
				t.Fatal("forged snooze reason")
			}
			out, e := s.DecideUsageRecommendation(a, decision, "reviewed evidence", nil, diskAdmin())
			expected := "rejected"
			if decision == "approved" {
				expected = "approved"
			}
			if e != nil || out.State != expected {
				t.Fatal(out, e)
			}
			if _, e = s.DecideUsageRecommendation(a, decision, "reviewed evidence", nil, diskAdmin()); e != nil {
				t.Fatal("decision replay", e)
			}
			var state string
			s.rdb.QueryRow(`SELECT state FROM usage_recommendations WHERE id=?`, r.ID).Scan(&state)
			if state != decision {
				t.Fatal(state)
			}
			if n := countRows(t, s, `SELECT COUNT(*) FROM ops_approvals`); n != 1 {
				t.Fatal(n)
			}
			called := false
			if _,
				e = s.consumeOpsApproval(out,
				"advice-dispatch",
				diskAdmin(),
				func(dbTx,
					OpsApproval) (string,
					error) {
					called = true
					return "",
						nil
				}); e == nil || called {
				t.Fatal("advice reached job factory")
			}
		})
	}
}

func TestUsageMigrationPreservesExistingApproval(t *testing.T) {
	s, _, policy, now := diskPolicyFixture(t)
	machine := mustEnroll(t, s, "legacy-disk", now)
	a,
		e := s.CreateOpsApproval(OpsApproval{ID: "legacy-approval",
		MachineID:      machine,
		Operation:      "quarantine",
		PolicyID:       policy.Policy.ID,
		PolicyRevision: policy.Policy.Revision,
		PolicyDigest:   policy.Policy.Digest,
		ItemDigest:     digestOf("items")},
		diskAdmin())
	if e != nil {
		t.Fatal(e)
	}
	var seq int
	var name, path string
	if e = s.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); e != nil {
		t.Fatal(e)
	}
	s.Close()
	db, e := sql.Open("sqlite", path)
	if e != nil {
		t.Fatal(e)
	}
	_, e = db.Exec(`CREATE TABLE legacy_policies(id TEXT NOT NULL, kind TEXT NOT NULL CHECK(kind='disk'), revision
INTEGER NOT NULL CHECK(revision>0), body TEXT NOT NULL, digest TEXT NOT NULL, created_by TEXT NOT
NULL, created_at TEXT NOT NULL, superseded_at TEXT, PRIMARY KEY(id, revision));
INSERT INTO
legacy_policies SELECT * FROM ops_policies;
DROP TRIGGER ops_policy_no_delete;
DROP TABLE
ops_policies;
ALTER TABLE legacy_policies RENAME TO ops_policies`)
	if e != nil {
		t.Fatal(e)
	}
	db.Close()
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	got, e := scanOpsApproval(s.rdb.QueryRow(`SELECT `+opsApprovalColumns+` FROM ops_approvals WHERE id=?`, a.ID))
	if e != nil || got.ItemDigest != a.ItemDigest || got.PolicyDigest != a.PolicyDigest {
		t.Fatal(got, e)
	}
	rows, e := s.rdb.Query(`PRAGMA foreign_key_check`)
	if e != nil {
		t.Fatal(e)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("migration broke child references")
	}
}

func TestUsageRecommendationImmutableReplay(t *testing.T) {
	s, m, _ := usageFixture(t)
	now := s.now().UTC()
	r := UsageRecommendation{ID: "advice",
		RuleID:         "lower-effort",
		MachineID:      m,
		Scope:          "machine",
		RuleVersion:    1,
		EvidenceDigest: digestOf("evidence"),
		EvidenceStart:  now.Add(-time.Hour),
		EvidenceEnd:    now,
		Confidence:     "medium",
		Proposer:       "rule"}
	if e := s.CreateUsageRecommendation(r); e != nil {
		t.Fatal(e)
	}
	bad := r
	bad.EstSavingsTokens = 10
	if e := s.CreateUsageRecommendation(bad); !errors.Is(e, ErrUsageConflict) {
		t.Fatal("changed replay accepted", e)
	}
	if _, e := s.db.Exec(`UPDATE usage_recommendations SET evidence_digest=? WHERE id=?`, digestOf("changed"), r.ID); e == nil {
		t.Fatal("mutable evidence")
	}
	records, e := s.UsageRecommendations(m)
	if e != nil || len(records) != 1 || records[0].State != "open" || records[0].ReopenAt != nil || records[0].CreatedAt.IsZero() {
		t.Fatal(records, e)
	}
}

func TestUsageQuotaEvidenceAndSharedAccountMembership(t *testing.T) {
	s, m, in := usageFixture(t)
	second := mustEnroll(t, s, "usage-second", s.now())
	account := UsageAccount{
		AccountID: usageTestHash, Provider: "openai", Plan: "pro",
		DiscoverySource: "api", LastSeen: s.now(),
	}
	for _, machine := range []string{m, second} {
		account.MachineID = machine
		if e := s.UpsertUsageAccount(account); e != nil {
			t.Fatal(e)
		}
	}
	accounts, e := s.UsageAccounts()
	if e != nil || len(accounts) != 2 || accounts[0].AccountID != accounts[1].AccountID {
		t.Fatal(accounts, e)
	}
	observed := 0.25
	window := in.Daily[0]
	window.Period = "2026-10-13T12:00:00Z"
	window.AccountID = usageTestHash
	window.Metrics.EstCostUnits = 0.2
	window.Metrics.ProviderUsageUnits = &observed
	window.Metrics.QuotaSource = "provider-reported"
	window.Metrics.CalibrationConfidence = "low"
	in.Window = []UsageAggregate{window}
	for _, machine := range []string{m, second} {
		if _, e = s.MergeUsageFile(machine, in); e != nil {
			t.Fatal(e)
		}
		rows, err := s.UsageContributions(machine, true)
		if err != nil || len(rows) != 1 {
			t.Fatal(rows, err)
		}
		got := rows[0].Metrics
		if got.EstCostUnits != 0.2 || got.ProviderUsageUnits == nil || *got.ProviderUsageUnits != observed || got.CalibrationConfidence != "low" {
			t.Fatal(got)
		}
	}
	invalid := UsageMetrics{InputUncached: (1 << 53) + 1}
	if invalid.validate() == nil {
		t.Fatal("integer precision overflow accepted")
	}
	defaults := DefaultUsagePolicy()
	if defaults.LinuxNice != 19 || defaults.LinuxIOClass != 3 || defaults.WindowsPriority != "below-normal" || !defaults.WindowsLowIOPriority {
		t.Fatal(defaults)
	}
}
