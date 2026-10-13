package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// UsagePolicy is storage-only configuration. Enrollment is explicitly off;
// labels become enabled only after a later collector enrollment implementation.
type UsagePolicy struct {
	LinuxNice, LinuxIOClass                                                                         int
	WindowsPriority                                                                                 string
	WindowsLowIOPriority                                                                            bool
	Enabled                                                                                         bool
	TaskLabels                                                                                      bool
	LabelMaxChars                                                                                   int
	CrossMachineJobs                                                                                bool
	ReadBytesPerSecond, BytesPerRun                                                                 int64
	WallSeconds, MemoryMiB, MaxLineBytes, MaxFiles                                                  int
	LoadPerCore                                                                                     float64
	PauseOnBattery                                                                                  bool
	BackfillDays, DailyRetentionDays, WindowRetentionDays, SessionRetentionDays, LabelRetentionDays int
	PriceTableVersion                                                                               string
	DailySpikeRatio, GrowthRatio, QuotaRiskPercent                                                  float64
	DailySpikeMinTokens, RunawayCalls, LongSessionCalls                                             int64
	LongSessionHours                                                                                int
}

func DefaultUsagePolicy() UsagePolicy {
	return UsagePolicy{
		LinuxNice: 19, LinuxIOClass: 3,
		WindowsPriority: "below-normal", WindowsLowIOPriority: true,
		TaskLabels: true, LabelMaxChars: 40,
		ReadBytesPerSecond: 20 << 20, BytesPerRun: 2 << 30,
		WallSeconds: 300, MemoryMiB: 128, MaxLineBytes: 1 << 20,
		MaxFiles: 200000, LoadPerCore: 0.8, PauseOnBattery: true,
		BackfillDays: 90, DailyRetentionDays: 400, WindowRetentionDays: 30,
		SessionRetentionDays: 90, LabelRetentionDays: 14,
		DailySpikeRatio: 2, GrowthRatio: 1.5, QuotaRiskPercent: 85,
		DailySpikeMinTokens: 5000000, RunawayCalls: 150,
		LongSessionCalls: 2000, LongSessionHours: 8,
	}
}
func (p UsagePolicy) validate() error {
	for _, days := range []int{p.DailyRetentionDays, p.WindowRetentionDays, p.SessionRetentionDays, p.LabelRetentionDays} {
		if days < 1 || int64(days) > math.MaxInt64/int64(24*time.Hour) {
			return ErrUsageInvalid
		}
	}
	if p.LinuxNice < 0 || p.LinuxNice > 19 || p.LinuxIOClass < 1 || p.LinuxIOClass > 3 ||
		!usageEnum(p.WindowsPriority, "below-normal", "idle") {
		return ErrUsageInvalid
	}
	if p.LabelMaxChars < 0 ||
		p.LabelMaxChars > 40 ||
		p.TaskLabels &&
			p.LabelMaxChars == 0 ||
		p.ReadBytesPerSecond <= 0 ||
		p.BytesPerRun <= 0 ||
		p.WallSeconds <= 0 ||
		p.MemoryMiB <= 0 ||
		p.MaxLineBytes <= 0 ||
		p.MaxLineBytes > 1<<20 ||
		p.MaxFiles <= 0 ||
		p.BackfillDays < 1 ||
		p.BackfillDays > 90 ||
		p.DailyRetentionDays < 1 ||
		p.WindowRetentionDays < 1 ||
		p.SessionRetentionDays < 1 ||
		p.LabelRetentionDays < 1 ||
		p.LabelRetentionDays > 14 ||
		p.LongSessionHours <= 0 ||
		p.DailySpikeMinTokens < 0 ||
		p.RunawayCalls < 1 ||
		p.LongSessionCalls < 1 {
		return ErrUsageInvalid
	}
	for _, v := range []float64{p.LoadPerCore, p.DailySpikeRatio, p.GrowthRatio, p.QuotaRiskPercent} {
		if math.IsNaN(v) || math.IsInf(v, 0) || v <= 0 {
			return ErrUsageInvalid
		}
	}
	if p.QuotaRiskPercent > 100 || p.PriceTableVersion != "" && validPolicyID(p.PriceTableVersion) != nil {
		return ErrUsageInvalid
	}
	return nil
}
func UsagePolicyPreviewDigest(id string, revision int64, p UsagePolicy) (string, error) {
	if validPolicyID(id) != nil || revision < 0 || p.validate() != nil {
		return "", ErrUsageInvalid
	}
	return digestOf(fmt.Sprintf("usage-policy:v1:%s:%d:%s", id, revision, mustScriptJSON(p))), nil
}

// PublishUsagePolicy publishes an immutable revision and audit in one transaction.
// The expected revision and preview bind exactly what the human reviewed.
func (s *Store) publishUsagePolicy(id string, expected int64, p UsagePolicy, preview string, audit AuditEntry) (OpsPolicy, error) {
	var out OpsPolicy
	if e := humanDiskAdmin(audit); e != nil {
		return out, e
	}
	want, e := UsagePolicyPreviewDigest(id, expected, p)
	if e != nil {
		return out, e
	}
	if want != preview {
		return out, ErrUsageConflict
	}
	tx, e := s.beginWrite(context.Background(), "usage_policy_publish")
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	var revision int64
	var kind, digest string
	e = tx.QueryRow(`SELECT revision,kind,digest FROM ops_policies WHERE id=? ORDER BY revision DESC LIMIT 1`, id).Scan(&revision, &kind, &digest)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if kind != "" && kind != "usage" {
		return out, ErrUsageConflict
	}
	body := mustScriptJSON(p)
	newDigest := digestOf(string(body))
	if digest == newDigest && (revision == expected || revision == expected+1) {
		out, e = scanOpsPolicy(tx.QueryRow(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at FROM ops_policies WHERE id=? AND revision=?`,
			id,
			revision))
		if e != nil {
			return out, e
		}
		audit.Action = AuditUsagePolicyApply
		audit.Subject = id
		audit.Detail = "unchanged usage policy " + newDigest
		audit.OK = true
		if e = s.recordAuditTx(tx, audit); e != nil {
			return out, e
		}
		return out, tx.Commit()
	}
	if revision != expected {
		return out, ErrUsageConflict
	}
	now := s.now().UTC()
	out = OpsPolicy{ID: id,
		Kind:      "usage",
		Revision:  revision + 1,
		Body:      json.RawMessage(body),
		Digest:    newDigest,
		CreatedBy: audit.AuthSubject,
		CreatedAt: now}
	if _, e = tx.Exec(`UPDATE ops_policies SET superseded_at=? WHERE id=? AND superseded_at IS NULL`, fmtTime(now), id); e != nil {
		return out, e
	}
	if _, e = tx.Exec(`INSERT INTO ops_policies VALUES (?,'usage',?,?,?,?,?,NULL)`,
		id,
		out.Revision,
		string(body),
		newDigest,
		audit.AuthSubject,
		fmtTime(now)); e != nil {
		return out, e
	}
	audit.Action = AuditUsagePolicyApply
	audit.Subject = id
	audit.Detail = newDigest
	audit.OK = true
	if e = s.recordAuditTx(tx, audit); e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func (s *Store) UsagePolicy(id string) (OpsPolicy, error) {
	return scanOpsPolicy(s.rdb.QueryRow(`SELECT id,kind,revision,body,digest,created_by,created_at,superseded_at
        FROM ops_policies
        WHERE id=? AND kind='usage' AND superseded_at IS NULL`,
		id))
}

// PublishUsagePolicy retains generic denial evidence without storing policy text.
func (s *Store) PublishUsagePolicy(id string, expected int64, p UsagePolicy, preview string, audit AuditEntry) (OpsPolicy, error) {
	audit.Reason = ""
	out, err := s.publishUsagePolicy(id, expected, p, preview, audit)
	if err != nil {
		audit.Action = AuditUsagePolicyApply
		audit.Subject = "usage-policy"
		audit.OK = false
		audit.Detail = "usage policy publication rejected"
		if e := s.RecordAudit(audit); e != nil {
			return out, e
		}
	}
	return out, err
}
