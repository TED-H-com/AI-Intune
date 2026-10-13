package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
)

var ErrUsageInvalid = errors.New("store: invalid usage record")
var ErrUsageConflict = errors.New("store: usage snapshot conflict")

// UsageMetrics contains numeric evidence only. Nil means not measured.
type UsageMetrics struct {
	Calls, Sessions, Turns                          int64
	InputUncached, CacheRead, Output, ContextTokens int64
	CacheWrite, Reasoning                           *int64
	EstCostUSD, EstCostUnits                        float64
	// Provider measurements stay distinct from local estimated cost units.
	ProviderUsageUnits                                                       *float64
	QuotaSource, CalibrationConfidence                                       string
	PriceTableVersion                                                        string
	ContextBucketCalls, ContextBucketTokens                                  [5]int64
	GapHistogram                                                             [6]int64
	CallsPerTurnP50, CallsPerTurnP90, CallsPerTurnMax                        int64
	ToolCalls                                                                map[string]int64
	CacheRebuildAfterGapTokens, LimitHits5h, LimitHitsWeekly, LimitHitsOther int64
	CounterResets, UnparsedLines, DedupedEvents                              int64
}
type UsageAggregate struct {
	Tool, AccountID, Model, Effort, EffortSource, SourceType, Period, ProjectHMAC string
	Metrics                                                                       UsageMetrics
}

// UsageFileSnapshot is a complete contribution, not a cumulative-counter delta.
// The collector normalizes counter resets before supplying this snapshot.
// Generation increases on rewrite/parser backfill; offsets increase within a generation.
type UsageFileSnapshot struct {
	FileHMAC                         string
	Generation, OffsetFrom, OffsetTo int64
	Daily, Window                    []UsageAggregate
}

func usageHash(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 16 && strings.ToLower(s) == s
}
func usageEnum(s string, values ...string) bool {
	for _, v := range values {
		if s == v {
			return true
		}
	}
	return false
}
func usageModel(s string) bool {
	return usageEnum(s,
		"unknown",
		"other",
		"claude-sonnet-4",
		"claude-opus-4",
		"claude-haiku-4",
		"gpt-5",
		"gpt-5-codex",
		"gpt-5.1",
		"gpt-5.1-codex",
		"gpt-5.2",
		"gpt-5.2-codex",
		"gpt-5.3-codex",
		"gpt-5.4") ||
		strings.HasPrefix(s, "other:") &&
			usageHash(strings.TrimPrefix(s, "other:"))
}
func (m UsageMetrics) validate() error {
	for _, value := range []float64{m.EstCostUSD, m.EstCostUnits} {
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return ErrUsageInvalid
		}
	}
	if m.ProviderUsageUnits != nil {
		value := *m.ProviderUsageUnits
		if math.IsNaN(value) || math.IsInf(value, 0) || value < 0 {
			return ErrUsageInvalid
		}
	}
	if !usageEnum(m.QuotaSource, "", "unknown", "local-estimate", "provider-reported") ||
		!usageEnum(m.CalibrationConfidence, "", "unknown", "low", "medium", "high") {
		return ErrUsageInvalid
	}
	if m.PriceTableVersion != "" && validPolicyID(m.PriceTableVersion) != nil {
		return ErrUsageInvalid
	}
	counts := []int64{
		m.Calls, m.Sessions, m.Turns,
		m.InputUncached, m.CacheRead, m.Output, m.ContextTokens,
		m.CallsPerTurnP50, m.CallsPerTurnP90, m.CallsPerTurnMax,
		m.CacheRebuildAfterGapTokens, m.LimitHits5h, m.LimitHitsWeekly,
		m.LimitHitsOther, m.CounterResets, m.UnparsedLines, m.DedupedEvents,
	}
	counts = append(counts, m.ContextBucketCalls[:]...)
	counts = append(counts, m.ContextBucketTokens[:]...)
	counts = append(counts, m.GapHistogram[:]...)
	for _, count := range m.ToolCalls {
		counts = append(counts, count)
	}
	for _, count := range []*int64{m.CacheWrite, m.Reasoning} {
		if count != nil {
			counts = append(counts, *count)
		}
	}
	for _, count := range counts {
		if count < 0 || count > (1<<53)-1 {
			return ErrUsageInvalid
		}
	}
	for k := range m.ToolCalls {
		if !usageEnum(k, "Bash", "Read", "Edit", "Write", "Task", "Glob", "Grep", "WebFetch", "WebSearch", "exec", "other") {
			return ErrUsageInvalid
		}
	}
	return nil
}
func (a UsageAggregate) validate(window bool) error {
	if !usageEnum(a.Tool, "claude", "codex") ||
		!(a.AccountID == "unknown" ||
			usageHash(a.AccountID)) ||
		!usageModel(a.Model) ||
		!usageEnum(a.Effort, "unknown", "minimal", "low", "medium", "high", "max", "xhigh", "ultra") ||
		!usageEnum(a.EffortSource, "recorded", "inferred", "unknown") ||
		!usageEnum(a.SourceType, "main", "subagent", "exec") ||
		a.ProjectHMAC != "" &&
			!usageHash(a.ProjectHMAC) {
		return ErrUsageInvalid
	}
	layout := "2006-01-02"
	if window {
		layout = "2006-01-02T15:00:00Z"
	}
	t, e := time.Parse(layout, a.Period)
	if e != nil || t.Format(layout) != a.Period {
		return ErrUsageInvalid
	}
	return a.Metrics.validate()
}

// canonicalUsageMetrics preserves absent measurements while normalizing signed zero.
// encoding/json already orders map keys and formats finite floats consistently.
func canonicalUsageMetrics(m UsageMetrics) UsageMetrics {
	if m.EstCostUSD == 0 {
		m.EstCostUSD = 0
	}
	if m.EstCostUnits == 0 {
		m.EstCostUnits = 0
	}
	if m.ProviderUsageUnits != nil && *m.ProviderUsageUnits == 0 {
		zero := float64(0)
		m.ProviderUsageUnits = &zero
	}
	if len(m.ToolCalls) == 0 {
		m.ToolCalls = nil
	}
	return m
}

func canonicalUsageAggregates(rows []UsageAggregate) []UsageAggregate {
	out := append([]UsageAggregate{}, rows...)
	for i := range out {
		out[i].Metrics = canonicalUsageMetrics(out[i].Metrics)
	}
	// The key consists of every dimension, excluding metrics.
	key := func(a UsageAggregate) string {
		a.Metrics = UsageMetrics{}
		return string(mustScriptJSON(a))
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

// MergeUsageFile atomically replaces a complete file contribution. Replays are
// harmless; stale/conflicting ranges fail closed. No audit contains usage bodies.
func (s *Store) MergeUsageFile(machine string, in UsageFileSnapshot) (bool, error) {
	if !usageHash(in.FileHMAC) || in.Generation < 0 || in.OffsetFrom < 0 || in.OffsetTo < in.OffsetFrom {
		return false, ErrUsageInvalid
	}
	for _, a := range in.Daily {
		if e := a.validate(false); e != nil {
			return false, e
		}
	}
	for _, a := range in.Window {
		if e := a.validate(true); e != nil {
			return false, e
		}
	}
	in.Daily = canonicalUsageAggregates(in.Daily)
	in.Window = canonicalUsageAggregates(in.Window)
	raw, e := json.Marshal(in)
	if e != nil || len(raw) > 2<<20 {
		return false, ErrUsageInvalid
	}
	digest := digestOf(string(raw))
	tx, e := s.beginWrite(context.Background(), "usage_merge")
	if e != nil {
		return false, e
	}
	defer tx.Rollback()
	var receipt string
	e = tx.QueryRow(`SELECT digest FROM usage_upload_receipts WHERE machine_id=? AND file_hmac=? AND generation=? AND offset_from=? AND offset_to=?`,
		machine,
		in.FileHMAC,
		in.Generation,
		in.OffsetFrom,
		in.OffsetTo).Scan(&receipt)
	if e == nil {
		if receipt == digest {
			return false, nil
		}
		return false, ErrUsageConflict
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return false, e
	}
	var gen, offset int64
	var old string
	e = tx.QueryRow(`SELECT generation,offset_to,digest FROM usage_files WHERE machine_id=? AND file_hmac=?`,
		machine,
		in.FileHMAC).Scan(&gen,
		&offset,
		&old)
	if e == nil {
		if gen == in.Generation && offset == in.OffsetTo && old == digest {
			return false, nil
		}
		if in.Generation < gen || in.Generation == gen && (in.OffsetFrom != offset || in.OffsetTo <= offset) || in.Generation > gen && in.OffsetFrom != 0 {
			return false, ErrUsageConflict
		}
	} else if !errors.Is(e, sql.ErrNoRows) {
		return false, e
	} else if in.OffsetFrom != 0 {
		return false, ErrUsageConflict
	}
	if _, e = tx.Exec(`INSERT INTO usage_files VALUES (?, ?, ?, ?, ?) ON CONFLICT(machine_id, file_hmac) DO UPDATE SET
generation=excluded.generation, offset_to=excluded.offset_to, digest=excluded.digest`,
		machine,
		in.FileHMAC,
		in.Generation,
		in.OffsetTo,
		digest); e != nil {
		return false, e
	}
	for i, rows := range [][]UsageAggregate{in.Daily, in.Window} {
		table, col := "usage_daily", "day"
		if i == 1 {
			table, col = "usage_window", "hour"
		}
		if _, e = tx.Exec(`DELETE FROM `+table+` WHERE machine_id=? AND file_hmac=?`, machine, in.FileHMAC); e != nil {
			return false, e
		}
		for _, a := range rows {
			body, _ := json.Marshal(a.Metrics)
			_, e = tx.Exec(`INSERT INTO `+table+` (machine_id,file_hmac,tool,account_id,model,effort,effort_source,source_type,`+col+`,project_hmac,metrics) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
				machine,
				in.FileHMAC,
				a.Tool,
				a.AccountID,
				a.Model,
				a.Effort,
				a.EffortSource,
				a.SourceType,
				a.Period,
				a.ProjectHMAC,
				string(body))
			if e != nil {
				return false, e
			}
		}
	}
	if _, e = tx.Exec(`INSERT INTO usage_upload_receipts VALUES (?,?,?,?,?,?)`,
		machine,
		in.FileHMAC,
		in.Generation,
		in.OffsetFrom,
		in.OffsetTo,
		digest); e != nil {
		return false, e
	}
	return true, tx.Commit()
}

// UsageContributions retains machine attribution so callers can pool known
// accounts without conflating unresolved accounts from different machines.
func (s *Store) UsageContributions(machine string, window bool) ([]UsageAggregate, error) {
	table, col := "usage_daily", "day"
	if window {
		table, col = "usage_window", "hour"
	}
	rows, e := s.rdb.Query(`SELECT tool,account_id,model,effort,effort_source,source_type,`+col+`,project_hmac,metrics FROM `+table+` WHERE machine_id=? ORDER BY `+col+`,file_hmac`,
		machine)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []UsageAggregate{}
	for rows.Next() {
		var a UsageAggregate
		var raw string
		if e = rows.Scan(&a.Tool, &a.AccountID, &a.Model, &a.Effort, &a.EffortSource, &a.SourceType, &a.Period, &a.ProjectHMAC, &raw); e != nil {
			return nil, e
		}
		if e = json.Unmarshal([]byte(raw), &a.Metrics); e != nil {
			return nil, e
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
