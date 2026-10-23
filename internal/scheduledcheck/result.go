// Package scheduledcheck defines the shared, safe scheduled-check summary.
package scheduledcheck

import (
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/boundedtext"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/scrubguard"
)

// HistoryLimit bounds failure streak reads per target. A full page is a lower bound.
const HistoryLimit = 32

type Schedule struct {
	ID, Name, ScriptID string
	Targets            []Result
}

type Result struct {
	MachineID, DisplayName string
	// Status is passed, failed, not_run, or pending.
	Status, Reason      string
	At                  time.Time
	InWindow            bool
	ConsecutiveFailures int
}

// Text applies the existing disclosure scrubbers before bounding a single line.
// Scrub before truncating so a credential crossing the length limit stays hidden.
func Text(raw string, limit int) string {
	raw = scriptcatalog.Redact(scrubguard.ScrubWithResult(raw).Value)
	raw, _, _ = boundedtext.Scrub(strings.TrimSpace(raw), limit)
	return raw
}

// Reason keeps only the first line; carriage returns and Unicode line breaks
// also terminate a reason rather than allowing extra notification lines.
func Reason(raw string) string {
	if i := strings.IndexAny(raw, "\r\n\u2028\u2029"); i >= 0 {
		raw = raw[:i]
	}
	return Text(raw, 240)
}
