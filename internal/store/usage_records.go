package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"time"
)

// No identity, credential, prompt, path or label fields are accepted by U-01.
// Restricted label storage/redaction belongs to U-08.
type UsageAccount struct {
	AccountID, MachineID, Provider, Plan, DiscoverySource, PinnedPlan string
	LastSeen                                                          time.Time
	Conflict                                                          bool
}

// Equal timestamps require identical content digests; conflicting snapshots fail closed.
func (s *Store) UpsertUsageAccount(a UsageAccount) error {
	if !usageHash(a.AccountID) ||
		!usageEnum(a.Provider, "anthropic", "openai", "xai", "github", "google", "other") ||
		!usageEnum(a.Plan, "unknown", "free", "pro", "max", "plus", "team", "business", "enterprise", "other") ||
		!usageEnum(a.DiscoverySource, "status", "metadata", "api", "dashboard", "overlay") ||
		a.PinnedPlan != "" &&
			!usageEnum(a.PinnedPlan, "unknown", "free", "pro", "max", "plus", "team", "business", "enterprise", "other") ||
		a.LastSeen.IsZero() {
		return ErrUsageInvalid
	}
	tx, e := s.beginWrite(context.Background(), "usage_account")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var old UsageAccount
	var seenNS int64
	e = tx.QueryRow(`SELECT account_id,machine_id,provider,plan,discovery_source,last_seen_ns,conflict,COALESCE(pinned_plan,'') FROM usage_accounts WHERE account_id=? AND machine_id=?`, a.AccountID, a.MachineID).Scan(&old.AccountID, &old.MachineID, &old.Provider, &old.Plan, &old.DiscoverySource, &seenNS, &old.Conflict, &old.PinnedPlan)
	if e == nil && seenNS == a.LastSeen.UnixNano() {
		old.LastSeen = a.LastSeen
		if a.PinnedPlan == "" {
			a.PinnedPlan = old.PinnedPlan
		}
		if digestOf(string(mustScriptJSON(old))) != digestOf(string(mustScriptJSON(a))) {
			return ErrUsageConflict
		}
		return nil
	}
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = tx.Exec(`INSERT INTO usage_accounts(account_id, machine_id, provider, plan, discovery_source, last_seen,
conflict, pinned_plan, last_seen_ns) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(account_id, machine_id) DO UPDATE
SET provider=excluded.provider, plan=excluded.plan, discovery_source=excluded.discovery_source,
last_seen=excluded.last_seen, last_seen_ns=excluded.last_seen_ns, conflict=excluded.conflict, pinned_plan=COALESCE(excluded.pinned_plan,
usage_accounts.pinned_plan) WHERE excluded.last_seen_ns>usage_accounts.last_seen_ns`,
		a.AccountID,
		a.MachineID,
		a.Provider,
		a.Plan,
		a.DiscoverySource,
		a.LastSeen.UTC().Format(time.RFC3339Nano),
		a.Conflict,
		nullStr(a.PinnedPlan), a.LastSeen.UnixNano())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UsageAccounts() ([]UsageAccount, error) {
	rows, e := s.rdb.Query(`SELECT account_id, machine_id, provider, plan, discovery_source, last_seen, conflict,
COALESCE(pinned_plan, '') FROM usage_accounts ORDER BY account_id, machine_id`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []UsageAccount{}
	for rows.Next() {
		var a UsageAccount
		var seen string
		if e = rows.Scan(&a.AccountID, &a.MachineID, &a.Provider, &a.Plan, &a.DiscoverySource, &seen, &a.Conflict, &a.PinnedPlan); e != nil {
			return nil, e
		}
		a.LastSeen = parseTime(seen)
		out = append(out, a)
	}
	return out, rows.Err()
}

type UsageSession struct {
	SessionHMAC, Tool, SourceType, ProjectHMAC, JobFingerprint string
	Models, Efforts                                            []string
	Start, End                                                 time.Time
	Metrics                                                    UsageMetrics
	MaxContext, MaxCallsPerTurn                                int64
}

func (a UsageSession) validate() error {
	if !usageHash(a.SessionHMAC) ||
		!usageEnum(a.Tool, "claude", "codex") ||
		!usageEnum(a.SourceType, "main", "subagent", "exec") ||
		a.ProjectHMAC != "" &&
			!usageHash(a.ProjectHMAC) ||
		a.JobFingerprint != "" &&
			!usageHash(a.JobFingerprint) ||
		a.Start.IsZero() ||
		a.End.Before(a.Start) ||
		a.MaxContext < 0 ||
		a.MaxCallsPerTurn < 0 ||
		len(a.Models) > 32 ||
		len(a.Efforts) > 16 {
		return ErrUsageInvalid
	}
	for _, v := range a.Models {
		if !usageModel(v) {
			return ErrUsageInvalid
		}
	}
	for _, v := range a.Efforts {
		if !usageEnum(v, "unknown", "minimal", "low", "medium", "high", "max", "xhigh", "ultra") {
			return ErrUsageInvalid
		}
	}
	return a.Metrics.validate()
}
func (s *Store) UpsertUsageSession(machine string, a UsageSession) error {
	if e := a.validate(); e != nil {
		return e
	}
	tx, e := s.beginWrite(context.Background(), "usage_session")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var raw string
	e = tx.QueryRow(`SELECT body FROM usage_sessions WHERE machine_id=? AND session_hmac=?`, machine, a.SessionHMAC).Scan(&raw)
	if e == nil {
		var old UsageSession
		if e = json.Unmarshal([]byte(raw), &old); e != nil {
			return e
		}
		if old.End.Equal(a.End) {
			if digestOf(string(mustScriptJSON(old))) != digestOf(string(mustScriptJSON(a))) {
				return ErrUsageConflict
			}
			return nil
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = tx.Exec(`INSERT INTO usage_sessions(machine_id, session_hmac, body, updated_at, end_ns)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(machine_id, session_hmac) DO UPDATE SET
body=excluded.body, updated_at=excluded.updated_at, end_ns=excluded.end_ns
WHERE excluded.end_ns>usage_sessions.end_ns`,
		machine, a.SessionHMAC, string(mustScriptJSON(a)), fmtTime(s.now().UTC()), a.End.UnixNano())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UsageSessions(machine string) ([]UsageSession, error) {
	rows, e := s.rdb.Query(`SELECT body FROM usage_sessions WHERE machine_id=? ORDER BY end_ns DESC,session_hmac LIMIT 500`, machine)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []UsageSession{}
	for rows.Next() {
		var raw string
		var a UsageSession
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(raw), &a); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type UsageJob struct {
	Fingerprint, Day, Model, Effort string
	Runs, MedianIntervalSeconds     int64
	TokensPerRun                    UsageMetrics
	FirstSeen, LastSeen             time.Time
}

func (s *Store) UpsertUsageJob(machine string, a UsageJob) error {
	day, e := time.Parse("2006-01-02", a.Day)
	if e != nil ||
		day.Format("2006-01-02") != a.Day ||
		!usageHash(a.Fingerprint) ||
		!usageModel(a.Model) ||
		!usageEnum(a.Effort, "unknown", "minimal", "low", "medium", "high", "max", "xhigh", "ultra") ||
		a.Runs < 0 ||
		a.MedianIntervalSeconds < 0 ||
		a.FirstSeen.IsZero() ||
		a.LastSeen.Before(a.FirstSeen) ||
		a.TokensPerRun.validate() != nil {
		return ErrUsageInvalid
	}
	tx, e := s.beginWrite(context.Background(), "usage_job")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var raw string
	e = tx.QueryRow(`SELECT body FROM usage_jobs WHERE machine_id=? AND fingerprint=? AND day=?`, machine, a.Fingerprint, a.Day).Scan(&raw)
	if e == nil {
		var old UsageJob
		if e = json.Unmarshal([]byte(raw), &old); e != nil {
			return e
		}
		if old.LastSeen.Equal(a.LastSeen) {
			if digestOf(string(mustScriptJSON(old))) != digestOf(string(mustScriptJSON(a))) {
				return ErrUsageConflict
			}
			return nil
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = tx.Exec(`INSERT INTO usage_jobs(machine_id, fingerprint, day, body, last_seen_ns)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(machine_id, fingerprint, day) DO UPDATE SET
body=excluded.body, last_seen_ns=excluded.last_seen_ns
WHERE excluded.last_seen_ns>usage_jobs.last_seen_ns`,
		machine, a.Fingerprint, a.Day, string(mustScriptJSON(a)), a.LastSeen.UnixNano())
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UsageJobs(machine string) ([]UsageJob, error) {
	rows, e := s.rdb.Query(`SELECT body FROM usage_jobs WHERE machine_id=? ORDER BY day DESC,fingerprint LIMIT 500`, machine)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []UsageJob{}
	for rows.Next() {
		var raw string
		var a UsageJob
		if e = rows.Scan(&raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(raw), &a); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

type UsageRecommendation struct {
	ID, RuleID, MachineID, Scope, ScopeHMAC, EvidenceDigest, Confidence, Proposer string
	RuleVersion, EstSavingsTokens                                                 int64
	EstSavingsUSD                                                                 float64
	EvidenceStart, EvidenceEnd                                                    time.Time
}

func UsageRecommendationItemDigest(a UsageRecommendation) string {
	return digestOf(string(mustScriptJSON(struct {
		ID, EvidenceDigest string
		RuleVersion        int64
	}{a.ID, a.EvidenceDigest, a.RuleVersion})))
}
func (s *Store) CreateUsageRecommendation(a UsageRecommendation) error {
	if validPolicyID(a.ID) != nil ||
		validPolicyID(a.RuleID) != nil ||
		a.RuleVersion < 1 ||
		!usageEnum(a.Scope, "account", "machine", "session", "job") ||
		a.Scope != "machine" &&
			!usageHash(a.ScopeHMAC) ||
		a.Scope == "machine" &&
			a.ScopeHMAC != "" ||
		!validLowerSHA256Digest(a.EvidenceDigest) ||
		!usageEnum(a.Confidence, "high", "medium", "low") ||
		a.Proposer != "rule" &&
			!(len(a.Proposer) > 6 &&
				a.Proposer[:6] == "agent:" &&
				validJobReadStoredIdentifier(a.Proposer[6:], 128)) ||
		a.EvidenceStart.IsZero() ||
		!a.EvidenceEnd.After(a.EvidenceStart) ||
		a.EstSavingsTokens < 0 ||
		(UsageMetrics{EstCostUSD: a.EstSavingsUSD}).validate() != nil {
		return ErrUsageInvalid
	}
	tx, e := s.beginWrite(context.Background(), "usage_recommendation")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var old UsageRecommendation
	var start, end string
	e = tx.QueryRow(`SELECT id, rule_id, rule_version, machine_id, scope, scope_hmac, evidence_digest, evidence_start,
evidence_end, est_savings_tokens, est_savings_usd, confidence, proposer FROM usage_recommendations
WHERE id=?`,
		a.ID).Scan(&old.ID,
		&old.RuleID,
		&old.RuleVersion,
		&old.MachineID,
		&old.Scope,
		&old.ScopeHMAC,
		&old.EvidenceDigest,
		&start,
		&end,
		&old.EstSavingsTokens,
		&old.EstSavingsUSD,
		&old.Confidence,
		&old.Proposer)
	if e == nil {
		if old.RuleID == a.RuleID &&
			old.RuleVersion == a.RuleVersion &&
			old.MachineID == a.MachineID &&
			old.Scope == a.Scope &&
			old.ScopeHMAC == a.ScopeHMAC &&
			old.EvidenceDigest == a.EvidenceDigest &&
			parseTime(start).Equal(a.EvidenceStart) &&
			parseTime(end).Equal(a.EvidenceEnd) &&
			old.EstSavingsTokens == a.EstSavingsTokens &&
			old.EstSavingsUSD == a.EstSavingsUSD &&
			old.Confidence == a.Confidence &&
			old.Proposer == a.Proposer {
			return nil
		}
		return ErrUsageConflict
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = tx.Exec(`INSERT INTO usage_recommendations VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'open',NULL,?,?)`,
		a.ID,
		a.RuleID,
		a.RuleVersion,
		a.MachineID,
		a.Scope,
		a.ScopeHMAC,
		a.EvidenceDigest,
		a.EvidenceStart.UTC().Format(time.RFC3339Nano),
		a.EvidenceEnd.UTC().Format(time.RFC3339Nano),
		a.EstSavingsTokens,
		a.EstSavingsUSD,
		a.Confidence,
		a.Proposer,
		fmtTime(s.now().UTC()))
	if e != nil {
		return e
	}
	return tx.Commit()
}

// UsageRecommendationRecord adds lifecycle metadata to immutable evidence.
type UsageRecommendationRecord struct {
	UsageRecommendation
	ApprovalID string
	Generation int64
	State      string
	ReopenAt   *time.Time
	CreatedAt  time.Time
}

func (s *Store) UsageRecommendations(machine string) ([]UsageRecommendationRecord, error) {
	rows, e := s.rdb.Query(`SELECT r.id, rule_id, rule_version, machine_id, scope, scope_hmac, evidence_digest, evidence_start,
evidence_end, est_savings_tokens, est_savings_usd, confidence, proposer, state, reopen_at,
created_at, COALESCE(c.approval_id,r.id), COALESCE(c.generation,0) FROM usage_recommendations r
LEFT JOIN usage_recommendation_cycles c ON c.recommendation_id=r.id WHERE machine_id=?`, machine)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []UsageRecommendationRecord{}
	for rows.Next() {
		var a UsageRecommendationRecord
		var start, end, created string
		var reopen sql.NullString
		if e = rows.Scan(&a.ID,
			&a.RuleID,
			&a.RuleVersion,
			&a.MachineID,
			&a.Scope,
			&a.ScopeHMAC,
			&a.EvidenceDigest,
			&start,
			&end,
			&a.EstSavingsTokens,
			&a.EstSavingsUSD,
			&a.Confidence,
			&a.Proposer,
			&a.State,
			&reopen,
			&created, &a.ApprovalID, &a.Generation); e != nil {
			return nil, e
		}
		a.EvidenceStart = parseTime(start)
		a.EvidenceEnd = parseTime(end)
		a.CreatedAt = parseTime(created)
		if reopen.Valid {
			t := parseTime(reopen.String)
			a.ReopenAt = &t
		}
		out = append(out, a)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	// Prioritize actionable cards before limiting. Compare parsed instants because
	// RFC3339 TEXT is not ordered by instant when fractions or offsets vary.
	sort.Slice(out, func(i, j int) bool {
		if (out[i].State == "open") != (out[j].State == "open") {
			return out[i].State == "open"
		}
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > 500 {
		out = out[:500]
	}
	return out, nil
}

// ReopenUsageRecommendation starts a fresh decision cycle once its snooze is due.
// Immutable evidence and previous approval receipts remain untouched.
func (s *Store) ReopenUsageRecommendation(id string) error {
	tx, err := s.beginWrite(context.Background(), "usage_reopen")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var raw sql.NullString
	err = tx.QueryRow(`SELECT reopen_at FROM usage_recommendations WHERE id=? AND state='snoozed'`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrUsageConflict
	}
	if err != nil {
		return err
	}
	if !raw.Valid {
		return ErrUsageConflict
	}
	reopen, err := time.Parse(time.RFC3339Nano, raw.String)
	if err != nil {
		return err
	}
	if s.now().Before(reopen) {
		return ErrUsageConflict
	}
	result, err := tx.Exec(`UPDATE usage_recommendations SET state='open',reopen_at=NULL WHERE id=? AND state='snoozed'`, id)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrUsageConflict
	}
	return tx.Commit()
}
