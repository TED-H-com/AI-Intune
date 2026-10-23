package store

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"
)

func TestUsageAppendRejectsDecreasesAndDroppedDimensions(t *testing.T) {
	for _, window := range []bool{false, true} {
		for _, kind := range []string{"calls", "tokens", "context", "cost", "optional", "tool", "histogram", "dimension"} {
			t.Run(kind+map[bool]string{false: "daily", true: "window"}[window], func(t *testing.T) {
				s, m, in := usageFixture(t)
				n := int64(10)
				cost := float64(10)
				in.Daily[0].Metrics = UsageMetrics{Calls: 10, Output: 10, ContextTokens: 10, EstCostUSD: 10, CacheWrite: &n, ProviderUsageUnits: &cost, ToolCalls: map[string]int64{"Read": 10}, GapHistogram: [6]int64{10}}
				if window {
					in.Window = append([]UsageAggregate(nil), in.Daily...)
					in.Window[0].Period = "2026-10-13T00:00:00Z"
					in.Daily = nil
				}
				if _, err := s.MergeUsageFile(m, in); err != nil {
					t.Fatal(err)
				}
				next := in
				next.OffsetFrom = in.OffsetTo
				next.OffsetTo++
				next.Daily = append([]UsageAggregate(nil), in.Daily...)
				next.Window = append([]UsageAggregate(nil), in.Window...)
				rows := next.Daily
				if window {
					rows = next.Window
				}
				switch kind {
				case "calls":
					rows[0].Metrics.Calls--
				case "tokens":
					rows[0].Metrics.Output--
				case "context":
					rows[0].Metrics.ContextTokens--
				case "cost":
					rows[0].Metrics.EstCostUSD--
				case "optional":
					rows[0].Metrics.CacheWrite = nil
				case "tool":
					rows[0].Metrics.ToolCalls = nil
				case "histogram":
					rows[0].Metrics.GapHistogram[0]--
				case "dimension":
					if window {
						next.Window = nil
					} else {
						next.Daily = nil
					}
				}
				if changed, err := s.MergeUsageFile(m, next); changed || !errors.Is(err, ErrUsageConflict) {
					t.Fatalf("%v %v", changed, err)
				}
				stored, err := s.UsageContributions(m, window)
				if err != nil || len(stored) != 1 || stored[0].Metrics.Calls != 10 {
					t.Fatal(stored, err)
				}
				next.Generation++
				next.OffsetFrom = 0
				if _, err = s.MergeUsageFile(m, next); err != nil {
					t.Fatal("rewrite", err)
				}
			})
		}
	}
}

func TestUsageMigrationAfterClockCorrection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "usage.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	m := mustEnroll(t, s, "clock", s.now())
	future := time.Date(2199, 1, 1, 0, 0, 0, 123, time.UTC)
	if _, err = s.db.Exec(`INSERT INTO usage_accounts(account_id,machine_id,provider,plan,discovery_source,last_seen,conflict,pinned_plan,last_seen_ns) VALUES (?,?,?,?,?,?,0,NULL,?)`, usageTestHash, m, "openai", "pro", "status", future.Format(time.RFC3339Nano), future.UnixNano()); err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct{ table, col, body string }{
		{"usage_sessions", "end_ns", string(mustScriptJSON(UsageSession{End: future}))},
		{"usage_jobs", "last_seen_ns", string(mustScriptJSON(UsageJob{LastSeen: future}))},
	} {
		if spec.table == "usage_sessions" {
			_, err = s.db.Exec(`INSERT INTO usage_sessions VALUES (?, 'session', ?, '2026-10-13T00:00:00Z',?)`, m, spec.body, future.UnixNano())
		} else {
			_, err = s.db.Exec(`INSERT INTO usage_jobs VALUES (?, 'job','2026-10-13',?,?)`, m, spec.body, future.UnixNano())
		}
		if err != nil {
			t.Fatal(err)
		}
		if _, err = s.db.Exec("ALTER TABLE " + spec.table + " DROP COLUMN " + spec.col); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.db.Exec(`ALTER TABLE usage_accounts DROP COLUMN last_seen_ns`); err != nil {
		t.Fatal(err)
	}
	s.Close()
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, spec := range []struct{ table, col string }{{"usage_accounts", "last_seen_ns"}, {"usage_sessions", "end_ns"}, {"usage_jobs", "last_seen_ns"}} {
		var ns int64
		if err = s.rdb.QueryRow("SELECT " + spec.col + " FROM " + spec.table).Scan(&ns); err != nil || ns != future.UnixNano() {
			t.Fatal(spec.table, ns, err)
		}
	}
}

func TestUsagePolicyRetentionDurationBounds(t *testing.T) {
	p := DefaultUsagePolicy()
	p.DailyRetentionDays = math.MaxInt
	if p.validate() == nil {
		t.Fatal("overflow accepted")
	}
}

func TestUsagePruneUsesPublishedPolicy(t *testing.T) {
	s, m, in := usageFixture(t)
	// Keep store-generated timestamps older than the prune retention cutoffs.
	s.nowFn = func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
	if _, err := s.MergeUsageFile(m, in); err != nil {
		t.Fatal(err)
	}
	p := DefaultUsagePolicy()
	p.DailyRetentionDays = 2
	p.WindowRetentionDays = 3
	p.SessionRetentionDays = 4
	digest, err := UsagePolicyPreviewDigest("usage", 0, p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := s.PublishUsagePolicy("usage", 0, p, digest, diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	r := UsageRecommendation{ID: "prune-advice", RuleID: "rule", RuleVersion: 1, MachineID: m, Scope: "machine", EvidenceDigest: digestOf("evidence"), EvidenceStart: s.now().Add(-time.Hour), EvidenceEnd: s.now(), Confidence: "high", Proposer: "rule"}
	if err = s.CreateUsageRecommendation(r); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateOpsApproval(OpsApproval{ID: r.ID, MachineID: m, Operation: "usage-recommendation-v1", PolicyID: policy.ID, PolicyRevision: policy.Revision, PolicyDigest: policy.Digest, ItemDigest: UsageRecommendationItemDigest(r)}, diskAdmin()); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`INSERT INTO ops_approvals(id,state,actor,machine_id,operation,policy_id,policy_revision,policy_digest,item_digest,created_at,deadline) SELECT 'disk-only',state,actor,machine_id,'quarantine',policy_id,policy_revision,policy_digest,item_digest,created_at,deadline FROM ops_approvals WHERE id=?`, r.ID); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	for _, sql := range []string{
		`INSERT INTO usage_window SELECT machine_id,file_hmac,tool,account_id,model,effort,effort_source,source_type,'2026-10-13T00:00:00Z',project_hmac,metrics FROM usage_daily`,
		`INSERT INTO usage_sessions VALUES (?, 'session', '{}', '2026-10-13T00:00:00Z',0)`,
		`INSERT INTO usage_jobs VALUES (?, 'job', '2026-10-13','{}',0)`,
		`INSERT INTO usage_accounts(account_id,machine_id,provider,plan,discovery_source,last_seen,last_seen_ns,conflict,pinned_plan) VALUES ('account',?,'openai','pro','status','2026-10-13T00:00:00Z',0,0,NULL)`,
		`INSERT INTO usage_recommendations VALUES ('old','rule',1,?,'machine','','digest','2026-10-12','2026-10-13',0,0,'high','open',NULL,'rule','2026-10-13T00:00:00Z')`,
	} {
		var err error
		if sql[:24] == "INSERT INTO usage_window" {
			_, err = s.db.Exec(sql)
		} else {
			_, err = s.db.Exec(sql, m)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.db.Exec(`INSERT INTO usage_recommendation_cycles VALUES ('old',1,'old:reopen:1')`); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec(`UPDATE usage_upload_receipts SET received_at='2026-10-13T00:00:00Z'`); err != nil {
		t.Fatal(err)
	}
	preview, err := s.Prune(now, DefaultRetention(), true)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := s.Prune(now, DefaultRetention(), false)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Total() != actual.Total() {
		t.Fatal(preview, actual)
	}
	for _, table := range []string{"usage_daily", "usage_window", "usage_sessions", "usage_jobs", "usage_accounts", "usage_recommendations", "usage_recommendation_cycles", "usage_upload_receipts"} {
		var n int
		if err = s.rdb.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil || n != 0 {
			t.Fatal(table, n, err)
		}
	}
	var approvals int
	if err = s.rdb.QueryRow(`SELECT count(*) FROM ops_approvals WHERE operation='usage-recommendation-v1'`).Scan(&approvals); err != nil || approvals != 0 {
		t.Fatal(approvals, err)
	}
	if err = s.rdb.QueryRow(`SELECT count(*) FROM ops_approvals WHERE id='disk-only'`).Scan(&approvals); err != nil || approvals != 1 {
		t.Fatal("disk approval removed", approvals, err)
	}
	var checkpoint int
	if err = s.rdb.QueryRow(`SELECT count(*) FROM usage_files`).Scan(&checkpoint); err != nil || checkpoint != 1 {
		t.Fatal(checkpoint, err)
	}
	if _, err = s.MergeUsageFile(m, in); err != nil {
		t.Fatal("latest replay", err)
	}
	rows, err := s.UsageContributions(m, false)
	if err != nil || len(rows) != 0 {
		t.Fatal("replay resurrected", rows, err)
	}
}

func TestUsageAppendAfterPruneDoesNotRestoreExpiredContributions(t *testing.T) {
	for _, published := range []bool{false, true} {
		t.Run(map[bool]string{false: "default", true: "published"}[published], func(t *testing.T) {
			s, machine, in := usageFixture(t)
			now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
			s.nowFn = func() time.Time { return now }
			p := DefaultUsagePolicy()
			if published {
				p.WindowRetentionDays = 3
				digest, err := UsagePolicyPreviewDigest("short-window", 0, p)
				if err != nil {
					t.Fatal(err)
				}
				if _, err = s.PublishUsagePolicy("short-window", 0, p, digest, diskAdmin()); err != nil {
					t.Fatal(err)
				}
			}
			in.Window = append([]UsageAggregate(nil), in.Daily...)
			in.Window[0].Period = now.Format(time.RFC3339)
			if changed, err := s.MergeUsageFile(machine, in); err != nil || !changed {
				t.Fatal(changed, err)
			}
			now = now.Add(time.Duration(p.WindowRetentionDays)*24*time.Hour + time.Hour)
			if _, err := s.Prune(now, DefaultRetention(), false); err != nil {
				t.Fatal(err)
			}
			next := in
			next.OffsetFrom = in.OffsetTo
			next.OffsetTo++
			recent := in.Window[0]
			recent.Period = now.Format(time.RFC3339)
			next.Window = append(append([]UsageAggregate(nil), in.Window...), recent)
			for _, generation := range []int64{0, 1} {
				next.Generation = generation
				if generation == 1 {
					next.OffsetFrom = 0
				}
				if changed, err := s.MergeUsageFile(machine, next); err != nil || !changed {
					t.Fatal(changed, err)
				}
				rows, err := s.UsageContributions(machine, true)
				if err != nil || len(rows) != 1 || rows[0].Period != recent.Period {
					t.Fatal("expired hours restored", rows, err)
				}
				if changed, err := s.MergeUsageFile(machine, next); err != nil || changed {
					t.Fatal("replay", changed, err)
				}
			}
		})
	}
}
