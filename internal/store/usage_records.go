package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"
)

// No identity, credential, prompt, path or label fields are accepted by U-01.
// Restricted label storage/redaction belongs to U-08.
type UsageAccount struct {
	AccountID, MachineID, Provider, Plan, DiscoverySource, PinnedPlan string
	LastSeen                                                          time.Time
	Conflict                                                          bool
}

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
	_, e = tx.Exec(`INSERT INTO usage_accounts(account_id, machine_id, provider, plan, discovery_source, last_seen,
conflict, pinned_plan) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(account_id, machine_id) DO UPDATE
SET provider=excluded.provider, plan=excluded.plan, discovery_source=excluded.discovery_source,
last_seen=excluded.last_seen, conflict=excluded.conflict, pinned_plan=COALESCE(excluded.pinned_plan,
usage_accounts.pinned_plan) WHERE excluded.last_seen>=usage_accounts.last_seen`,
		a.AccountID,
		a.MachineID,
		a.Provider,
		a.Plan,
		a.DiscoverySource,
		fmtTime(a.LastSeen),
		a.Conflict,
		nullStr(a.PinnedPlan))
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
	_, e = tx.Exec(`INSERT INTO usage_sessions VALUES (?, ?, ?, ?) ON CONFLICT(machine_id, session_hmac) DO UPDATE SET
body=excluded.body, updated_at=excluded.updated_at WHERE json_extract(excluded.body,
'$.End')>=json_extract(usage_sessions.body, '$.End')`, machine, a.SessionHMAC, string(mustScriptJSON(a)), fmtTime(s.now().UTC()))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UsageSessions(machine string) ([]UsageSession, error) {
	rows, e := s.rdb.Query(`SELECT body FROM usage_sessions WHERE machine_id=? ORDER BY session_hmac LIMIT 500`, machine)
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
	_, e = tx.Exec(`INSERT INTO usage_jobs VALUES (?, ?, ?, ?) ON CONFLICT(machine_id, fingerprint, day) DO UPDATE SET
body=excluded.body WHERE json_extract(excluded.body, '$.LastSeen')>=json_extract(usage_jobs.body,
'$.LastSeen')`, machine, a.Fingerprint, a.Day, string(mustScriptJSON(a)))
	if e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) UsageJobs(machine string) ([]UsageJob, error) {
	rows, e := s.rdb.Query(`SELECT body FROM usage_jobs WHERE machine_id=? ORDER BY day,fingerprint LIMIT 500`, machine)
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
			start == fmtTime(a.EvidenceStart) &&
			end == fmtTime(a.EvidenceEnd) &&
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
	_,
		e = tx.Exec(`INSERT INTO usage_recommendations VALUES (?,?,?,?,?,?,?,?,?,?,?,?, 'open',NULL,?,?)`,
		a.ID,
		a.RuleID,
		a.RuleVersion,
		a.MachineID,
		a.Scope,
		a.ScopeHMAC,
		a.EvidenceDigest,
		fmtTime(a.EvidenceStart),
		fmtTime(a.EvidenceEnd),
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
	State     string
	ReopenAt  *time.Time
	CreatedAt time.Time
}

func (s *Store) UsageRecommendations(machine string) ([]UsageRecommendationRecord, error) {
	rows, e := s.rdb.Query(`SELECT id, rule_id, rule_version, machine_id, scope, scope_hmac, evidence_digest, evidence_start,
evidence_end, est_savings_tokens, est_savings_usd, confidence, proposer, state, reopen_at,
created_at FROM usage_recommendations WHERE machine_id=? ORDER BY created_at, id LIMIT 500`, machine)
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
			&created); e != nil {
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
	return out, rows.Err()
}
