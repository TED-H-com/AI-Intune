// Package errlog defines the shared fleet error record and its text sanitizers.
// Callers must redact messages and string values in context before persistence.
package errlog

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"
)

// Record is one JSON Lines error record shared by fleet components.
// TS is encoded as RFC3339 by encoding/json. Count includes repeated occurrences.
type Record struct {
	TS          time.Time      `json:"ts"`
	MachineID   string         `json:"machine_id"`
	Component   string         `json:"component"`
	Version     string         `json:"version"`
	Level       string         `json:"level"`
	Code        string         `json:"code"`
	Msg         string         `json:"msg"`
	Fingerprint string         `json:"fingerprint"`
	Count       int            `json:"count"`
	Context     map[string]any `json:"context"`
}

const redacted = "[REDACTED]"

// Keep detection and replacement on the same patterns so ingest can apply the
// same policy as writers. Patterns intentionally accept short synthetic tokens.
var secretPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)`),
	regexp.MustCompile(`(?i)\bAuthorization["']?\s*[:=]\s*["']?(?:(?:Bearer|Basic|Digest|Token)\s+)?[^\s"'<>;,}\]]+`),
	regexp.MustCompile(`(?i)\bBearer\s+[^\s"'<>;,}\]]+`),
	regexp.MustCompile(`(?i)\b(?:[a-z][a-z0-9_]*_)?(?:token|password|secret|api_key|apikey)["']?\s*[:=]\s*(?:"[^"\r\n]*"|'[^'\r\n]*'|[^\s&;,"'<>}\]]+)`),
	regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s/@]+@`),
	regexp.MustCompile(`\b(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`),
	regexp.MustCompile(`\btskey-[A-Za-z0-9_-]+`),
	regexp.MustCompile(`\b[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}\b`),
}

// Redact removes recognizable credentials and email addresses from text.
// It is idempotent; redacted markers do not themselves match secret patterns.
func Redact(s string) string {
	for _, pattern := range secretPatterns {
		s = pattern.ReplaceAllString(s, redacted)
	}
	return s
}

// ContainsSecret reports whether text contains a shape covered by Redact.
// Opaque credentials without a recognizable shape or label cannot be detected.
func ContainsSecret(s string) bool {
	for _, pattern := range secretPatterns {
		if pattern.MatchString(s) {
			return true
		}
	}
	return false
}

var normalizations = []struct {
	pattern     *regexp.Regexp
	replacement string
}{
	{regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`), "<uuid>"},
	{regexp.MustCompile(`(?i)\b0x[0-9a-f]+\b|\b[0-9a-f]{8,}\b`), "<hex>"},
	{regexp.MustCompile(`(?:[A-Za-z]:\\|\\\\|/|\./|\.\./|~/)[^\s"'<>),;\]}]+`), "<path>"},
	{regexp.MustCompile(`:\d+\b`), ":<port>"},
	{regexp.MustCompile(`\b\d+(?:\.\d+)*\b`), "<num>"},
}

// Normalize replaces variable UUIDs, hex values (0x-prefixed or at least eight
// hex digits), paths, ports and numbers, then collapses whitespace. Case and
// other wording are preserved so distinct failures remain distinguishable.
func Normalize(msg string) string {
	for _, rule := range normalizations {
		msg = rule.pattern.ReplaceAllString(msg, rule.replacement)
	}
	return strings.Join(strings.Fields(msg), " ")
}

// Fingerprint returns the first 16 hex characters of the normalized record hash.
func Fingerprint(component, code, msg string) string {
	sum := sha256.Sum256([]byte(component + "|" + code + "|" + Normalize(msg)))
	return hex.EncodeToString(sum[:8])
}
