// Package diskpolicy defines the closed disk contract shared by Hub and agent.
package diskpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/teddashh/AI-Intune/internal/maintenance"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"io"
	"path"
	"sort"
	"strings"
)

// DiskPolicy is a closed, versioned contract. ProtectPaths adds protections;
// built-in credentials/backups, generated images, models, user data and all
// repositories are unconditional and cannot be overridden by this document.
type DiskPolicy struct {
	Growth            *DiskGrowthPolicy `json:"growth,omitempty"`
	DataMounts        []string          `json:"data_mounts,omitempty"`
	CanaryDays        int               `json:"canary_days,omitempty"`
	SchemaVersion     int               `json:"schema_version"`
	SafeTier          DiskSafeTier      `json:"safe_tier"`
	ProtectPaths      []string          `json:"protect_paths"`
	Thresholds        DiskThresholds    `json:"thresholds"`
	QuarantineTTLDays int               `json:"quarantine_ttl_days"`
	ScanBudgets       DiskScanBudgets   `json:"scan_budgets"`
}
type DiskGrowthPolicy struct {
	GBPerHour     int `json:"gb_per_hour"`
	WindowMinutes int `json:"window_minutes"`
}

func (p DiskGrowthPolicy) Valid() bool {
	return p.GBPerHour >= 1 && p.GBPerHour <= 1000000 && p.WindowMinutes >= 10 && p.WindowMinutes <= 1440
}

type DiskSafeTier struct {
	UserTmpMinDays int    `json:"user_tmp_min_days"`
	VarTmpMinDays  int    `json:"var_tmp_min_days"`
	DockerMinHours int    `json:"docker_min_hours"`
	DockerMode     string `json:"docker_mode"`
	JournaldMaxMiB int    `json:"journald_max_mib"`
	CargoMinDays   int    `json:"cargo_min_days"`
	UVMode         string `json:"uv_mode"`
	NPMMode        string `json:"npm_mode"`
	ToolCacheMode  string `json:"tool_cache_mode"`
}
type DiskThresholds struct {
	WarnPercent            int `json:"warn_percent"`
	CriticalPercent        int `json:"critical_percent"`
	DeepReportAbovePercent int `json:"deep_report_above_percent"`
}
type DiskScanBudgets struct {
	MaxItems   int `json:"max_items"`
	MaxEntries int `json:"max_entries"`
	MaxSeconds int `json:"max_seconds"`
}

// DiskProtectionRules is the mandatory adapter protection contract, separate
// from caller-controlled policy JSON. Returned slices are copies.
type DiskProtectionRules struct {
	BuiltInNames     []string `json:"built_in_names"`
	ProtectedClasses []string `json:"protected_classes"`
	AdditivePaths    []string `json:"additive_paths"`
}

var diskBuiltInNames = append([]string(nil), maintenance.BuiltinProtect...)

func (p DiskPolicy) Protections() DiskProtectionRules {
	return DiskProtectionRules{append([]string{}, diskBuiltInNames...), []string{"credentials", "credential-backups", "~/.codex/generated_images", "active-models", "user-data", "all-repository-roots", "open-descriptors", "locks"}, append([]string{}, p.ProtectPaths...)}
}

func DefaultDiskPolicy() DiskPolicy {
	return DiskPolicy{nil, nil, 0, 1, DiskSafeTier{10, 14, 168, "dangling-and-build-cache", 500, 30, "lock-aware-prune", "verify-only", "native-gc-holder-aware"}, []string{}, DiskThresholds{85, 93, 80}, 7, DiskScanBudgets{500, 200000, 600}}
}
func CanonicalDiskPolicy(raw json.RawMessage) (DiskPolicy, json.RawMessage, string, error) {
	var p DiskPolicy
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, nil, "", errors.New("invalid disk policy JSON")
	}
	if err := d.Decode(new(any)); err != io.EOF {
		return p, nil, "", errors.New("policy must be one JSON document")
	}
	if p.Growth != nil && !p.Growth.Valid() {
		return p, nil, "", errors.New("invalid disk growth policy")
	}
	t := p.SafeTier
	b := p.ScanBudgets
	h := p.Thresholds
	if len(p.DataMounts) > 15 || p.CanaryDays < 0 || p.CanaryDays > 90 || p.SchemaVersion != 1 || p.QuarantineTTLDays != 7 || t.UserTmpMinDays < 10 || t.UserTmpMinDays > 3650 || t.VarTmpMinDays < 14 || t.VarTmpMinDays > 3650 || t.DockerMinHours < 168 || t.DockerMinHours > 87600 || t.CargoMinDays < 30 || t.CargoMinDays > 3650 || t.JournaldMaxMiB < 500 || t.JournaldMaxMiB > 1048576 || t.DockerMode != "dangling-and-build-cache" || t.UVMode != "lock-aware-prune" || t.NPMMode != "verify-only" || t.ToolCacheMode != "native-gc-holder-aware" || h.DeepReportAbovePercent < 1 || h.DeepReportAbovePercent >= h.WarnPercent || h.WarnPercent >= h.CriticalPercent || h.CriticalPercent > 100 || b.MaxItems < 1 || b.MaxItems > 500 || b.MaxEntries < 1 || b.MaxEntries > 200000 || b.MaxSeconds < 1 || b.MaxSeconds > 600 || len(p.ProtectPaths) > 100 {
		return p, nil, "", errors.New("disk policy outside safe bounds")
	}
	p.ProtectPaths = append([]string{}, p.ProtectPaths...)
	sort.Strings(p.ProtectPaths)
	for i, v := range p.ProtectPaths {
		if len(v) > 1024 || !strings.HasPrefix(v, "/") || path.Clean(v) != v || strings.ContainsAny(v, "\x00\r\n") || scriptcatalog.Redact(v) != v || (i > 0 && p.ProtectPaths[i-1] == v) {
			return p, nil, "", errors.New("invalid or duplicate additive protect path")
		}
	}
	sort.Strings(p.DataMounts)
	for i, v := range p.DataMounts {
		if len(v) > 128 || !strings.HasPrefix(v, "/") || v == "/" || path.Clean(v) != v || strings.ContainsAny(v, "\x00\r\n") || scriptcatalog.Redact(v) != v || (i > 0 && p.DataMounts[i-1] == v) {
			return p, nil, "", errors.New("invalid data mount")
		}
	}
	canonical, _ := json.Marshal(p)
	return p, canonical, "sha256:" + scriptcatalog.Digest(canonical), nil
}
