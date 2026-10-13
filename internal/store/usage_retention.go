package store

import (
	"database/sql"
	"encoding/json"
	"time"
)

// U-01 has no policy-to-machine assignment yet. With multiple current usage
// policies, use the longest configured horizon in each class. Without a current
// policy, use the defaults. Labels are deferred to U-08 and have no table to prune yet.
func usagePruneJobs(tx interface {
	Query(string, ...any) (*sql.Rows, error)
}) ([]pruneJob, error) {
	p := DefaultUsagePolicy()
	rows, err := tx.Query(`SELECT body FROM ops_policies WHERE kind='usage' AND superseded_at IS NULL`)
	if err != nil {
		return nil, err
	}
	first := true
	for rows.Next() {
		var raw string
		if err = rows.Scan(&raw); err != nil {
			rows.Close()
			return nil, err
		}
		var next UsagePolicy
		if err = json.Unmarshal([]byte(raw), &next); err != nil {
			rows.Close()
			return nil, err
		}
		if err = next.validate(); err != nil {
			rows.Close()
			return nil, err
		}
		if first {
			p = next
			first = false
		} else {
			p.DailyRetentionDays = max(p.DailyRetentionDays, next.DailyRetentionDays)
			p.WindowRetentionDays = max(p.WindowRetentionDays, next.WindowRetentionDays)
			p.SessionRetentionDays = max(p.SessionRetentionDays, next.SessionRetentionDays)
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return usageJobsForPolicy(p), nil
}

func usageJobsForPolicy(p UsagePolicy) []pruneJob {
	var out []pruneJob
	for _, spec := range []struct {
		table, col string
		days       int
	}{
		{"usage_daily", "day", p.DailyRetentionDays}, {"usage_window", "hour", p.WindowRetentionDays},
		{"usage_sessions", "updated_at", p.SessionRetentionDays}, {"usage_jobs", "day", p.SessionRetentionDays},
		{"usage_accounts", "last_seen", p.DailyRetentionDays}, {"usage_upload_receipts", "received_at", p.DailyRetentionDays},
		{"usage_recommendations", "created_at", p.SessionRetentionDays},
	} {
		out = append(out, pruneJob{table: spec.table, cutCol: spec.col, protectExpr: "1", class: RetentionClass("usage"), usageHorizon: time.Duration(spec.days) * 24 * time.Hour})
	}
	out = append(out, pruneJob{table: "ops_approvals", cutCol: "created_at", protectExpr: "operation='usage-recommendation-v1'", class: RetentionClass("usage"), usageHorizon: time.Duration(p.SessionRetentionDays) * 24 * time.Hour})
	return out
}
func allPruneJobs(tx interface {
	Query(string, ...any) (*sql.Rows, error)
}) ([]pruneJob, error) {
	usage, err := usagePruneJobs(tx)
	return append(append([]pruneJob(nil), pruneJobs...), usage...), err
}
func (j pruneJob) horizon(p RetentionPolicy) time.Duration {
	if j.usageHorizon != 0 {
		return j.usageHorizon
	}
	return j.class.horizon(p)
}
