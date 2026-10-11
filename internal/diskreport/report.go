// Package diskreport is the typed private report contract shared by Hub and agent.
package diskreport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"io"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const MaxBytes = 2 << 20
const MaxChunk = 64 << 10

type Identity struct {
	Dev     uint64 `json:"dev"`
	Inode   uint64 `json:"inode"`
	Type    uint32 `json:"type"`
	Size    int64  `json:"size"`
	MtimeNS int64  `json:"mtime_ns"`
	CtimeNS int64  `json:"ctime_ns"`
}
type Item struct {
	ID               string   `json:"id"`
	Category         string   `json:"category"`
	PrivatePath      string   `json:"private_path,omitempty"`
	DisplayPath      string   `json:"display_path,omitempty"`
	AllocatedBytes   int64    `json:"allocated_bytes"`
	LogicalBytes     int64    `json:"logical_bytes"`
	LastUsed         string   `json:"last_used"`
	LastUsedSource   string   `json:"last_used_source"`
	EvidenceStrength string   `json:"evidence_strength"`
	OwnerUID         int64    `json:"owner_uid"`
	OwnerApp         string   `json:"owner_app"`
	Confidence       string   `json:"confidence"`
	SuggestedAction  string   `json:"suggested_action"`
	Reversible       bool     `json:"reversible"`
	ExclusionReason  string   `json:"exclusion_reason"`
	Identity         Identity `json:"identity"`
	ContentDigest    string   `json:"content_digest,omitempty"`
	PID              int      `json:"pid,omitempty"`
	StartTime        string   `json:"start_time,omitempty"`
	BootID           string   `json:"boot_id,omitempty"`
	HolderCount      int      `json:"holder_count,omitempty"`
	AgeBucket        string   `json:"age_bucket,omitempty"`
}
type Aggregate struct {
	Count          int   `json:"count"`
	AllocatedBytes int64 `json:"allocated_bytes"`
}
type Report struct {
	Schema            string               `json:"schema"`
	PolicyID          string               `json:"policy_id"`
	PolicyDigest      string               `json:"policy_digest"`
	Items             []Item               `json:"items"`
	Excluded          map[string]Aggregate `json:"excluded"`
	InaccessibleRoots []string             `json:"inaccessible_roots"`
	Truncated         bool                 `json:"truncated"`
	Partial           bool                 `json:"partial"`
	Entries           int                  `json:"entries"`
	Notices           []string             `json:"notices"`
}
type Chunk struct {
	Sequence int    `json:"sequence"`
	Digest   string `json:"digest"`
	Data     []byte `json:"data"`
}
type Complete struct {
	Digest    string `json:"digest"`
	ItemCount int    `json:"item_count"`
}
type Receipt struct {
	ID     string `json:"id"`
	Digest string `json:"digest"`
}

func Digest(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func Decode(raw []byte) (Report, []byte, error) {
	var r Report
	if len(raw) > MaxBytes {
		return r, nil, fmt.Errorf("report too large")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&r); err != nil {
		return r, nil, fmt.Errorf("invalid report")
	}
	if d.Decode(new(any)) != io.EOF || r.Schema != "disk-deep/v1" || len(r.Items) > 500 || r.Entries < 0 || r.Entries > 200000 || len(r.Notices) > 32 || len(r.InaccessibleRoots) > 16 || len(r.Excluded) > 16 {
		return r, nil, fmt.Errorf("invalid report bounds")
	}
	seen := map[string]bool{}
	for _, i := range r.Items {
		if i.ID == "" || len(i.ID) > 128 || seen[i.ID] || len(i.PrivatePath) > 4096 || !filepath.IsAbs(i.PrivatePath) || filepath.Clean(i.PrivatePath) != i.PrivatePath || strings.ContainsAny(i.PrivatePath, "\x00\r\n") || i.DisplayPath != "" || i.AllocatedBytes < 0 || i.LogicalBytes < 0 || i.OwnerUID < 0 || len(i.OwnerApp) > 128 || len(i.ExclusionReason) > 256 {
			return r, nil, fmt.Errorf("invalid report item")
		}
		seen[i.ID] = true
		switch i.Category {
		case "app-update-backups", "installer-leftovers", "release-build-directories", "unused-docker-images", "caches-models", "orphaned-processes", "agent-session-stores", "duplicate-archives":
		default:
			return r, nil, fmt.Errorf("invalid category")
		}
		switch i.Confidence {
		case "high", "medium", "low":
		default:
			return r, nil, fmt.Errorf("invalid confidence")
		}
		switch i.SuggestedAction {
		case "quarantine", "delete", "keep", "investigate":
		default:
			return r, nil, fmt.Errorf("invalid action")
		}
		if i.EvidenceStrength != "weak" && i.EvidenceStrength != "strong" && i.EvidenceStrength != "unknown" {
			return r, nil, fmt.Errorf("invalid evidence")
		}
	}
	raw, err := json.Marshal(r)
	if len(raw) > MaxBytes {
		return r, nil, fmt.Errorf("canonical report too large")
	}
	return r, raw, err
}

// Display exposes a fixed prefix and basename only. Credentials and ancestor
// names are never used in a public projection.
func Display(path string) string {
	base := scriptcatalog.Redact(ScrubDisplay(filepath.Base(path)))
	if len(base) > 80 {
		base = "item"
	}
	for _, word := range []string{"secret", "token", "password", "credential"} {
		if strings.Contains(strings.ToLower(base), word) {
			base = "protected-name"
		}
	}
	return "~/…/" + base
}

// ScrubDisplay preserves readable text while removing Unicode/control spoofing.
func ScrubDisplay(value string) string {
	value, _, _ = boundedtext.Scrub(value, 4096)
	return value
}
func StoredItem(i Item) Item {
	i.DisplayPath = Display(i.PrivatePath)
	i.OwnerApp = ScrubDisplay(i.OwnerApp)
	i.ExclusionReason = ScrubDisplay(i.ExclusionReason)
	return i
}
func PublicItem(i Item) Item {
	display := i.DisplayPath
	if i.PrivatePath != "" {
		display = Display(i.PrivatePath)
	}
	if !strings.HasPrefix(display, "~/…/") || strings.ContainsAny(strings.TrimPrefix(display, "~/…/"), "/\\") {
		display = "~/…/item"
	}
	i.DisplayPath = Display(strings.TrimPrefix(display, "~/…/"))
	i.PrivatePath = ""
	i.Identity = Identity{}
	i.ExclusionReason = ""
	i.ContentDigest = ""
	i.BootID = ""
	i.StartTime = ""
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,128}$`).MatchString(i.ID) {
		i.ID = "item"
	}
	switch i.OwnerApp {
	case "docker", "sandbox helper", "unknown":
	default:
		i.OwnerApp = "unknown"
	}
	switch i.LastUsedSource {
	case "atime", "all-container references", "process start ticks":
	default:
		i.LastUsedSource = "unknown"
	}
	if _, err := time.Parse(time.RFC3339Nano, i.LastUsed); err != nil {
		i.LastUsed = ""
	}
	switch i.AgeBucket {
	case "0-7 days", "7-30 days", "30-90 days", "90+ days":
	default:
		i.AgeBucket = ""
	}
	return i
}

// PublicReport never projects free-form machine notices, root paths or map keys.
func PublicReport(r Report) Report {
	r.Items = []Item{}
	roots := make([]string, len(r.InaccessibleRoots))
	for n := range roots {
		roots[n] = fmt.Sprintf("reviewed-root-%d", n+1)
	}
	r.InaccessibleRoots = roots
	noAtime := false
	for _, notice := range r.Notices {
		noAtime = noAtime || strings.HasSuffix(notice, "skipped: no O_NOATIME permission") || notice == "Subtrees skipped: no O_NOATIME permission."
	}
	r.Notices = []string{"Access times may be weak under relatime/noatime. Unknown generation and holder evidence requires investigation."}
	if noAtime {
		r.Notices = append(r.Notices, "Read operations skipped: no O_NOATIME permission")
	}
	if r.Partial {
		r.Notices = append(r.Notices, "Some inventory adapters or roots were unavailable; no clean verdict.")
	}
	aggregates := map[string]Aggregate{}
	for _, v := range r.Excluded {
		a := aggregates["protected"]
		a.Count += v.Count
		a.AllocatedBytes += v.AllocatedBytes
		aggregates["protected"] = a
	}
	r.Excluded = aggregates
	return r
}

// SafeSummary preserves only the two public receipt bindings. Ordinary output
// redaction deliberately removes opaque long strings and cannot preserve hashes.
func SafeSummary(raw []byte) (Receipt, string, error) {
	var r Receipt
	if len(raw) > 1024 {
		return r, "", fmt.Errorf("invalid report summary")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&r) != nil || d.Decode(new(any)) != io.EOF || !regexp.MustCompile(`^report-[a-zA-Z0-9_-]{1,128}$`).MatchString(r.ID) || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(r.Digest) {
		return r, "", fmt.Errorf("invalid report summary")
	}
	canonical, _ := json.Marshal(r)
	return r, string(canonical), nil
}
