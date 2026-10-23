// Package boundedtext validates human audit explanations without redacting prose.
package boundedtext

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxReasonRunes is the maximum length of a normalized audit reason.
const MaxReasonRunes = 500

var assignments = regexp.MustCompile(`(?i)\b(password|passwd|token|secret|api[_-]?key)\s*[:=]\s*\S+`)
var bearer = regexp.MustCompile(`(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}`)
var known = regexp.MustCompile(`\b(?:cst_[a-f0-9]{64}|eyJ[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{16,}|sk-[A-Za-z0-9_-]{16,}|AKIA[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{16,})`)
var runs = regexp.MustCompile(`[A-Za-z0-9_+/=-]{32,}`)

// Reason trims surrounding whitespace, counts Unicode characters, and returns
// rule-specific errors which never echo potential credentials.
func Reason(raw string) (string, error) {
	if !utf8.ValidString(raw) {
		return "", fmt.Errorf("reason is not valid UTF-8")
	}
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", fmt.Errorf("reason is empty")
	}
	if n := utf8.RuneCountInString(s); n > MaxReasonRunes {
		return "", fmt.Errorf("reason is %d characters; maximum is %d", n, MaxReasonRunes)
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == '\u2028' || r == '\u2029' {
			return "", fmt.Errorf("reason contains a control character")
		}
	}
	pattern := ""
	switch {
	case assignments.MatchString(s):
		pattern = "password/token/secret assignment"
	case bearer.MatchString(s):
		pattern = "bearer token"
	case strings.Contains(s, "-----BEGIN "):
		pattern = "PEM block"
	case known.MatchString(s):
		pattern = "known token prefix"
	default:
		for _, run := range runs.FindAllString(s, -1) {
			var lower, upper, digit bool
			unique := map[rune]bool{}
			for _, r := range run {
				lower = lower || unicode.IsLower(r)
				upper = upper || unicode.IsUpper(r)
				digit = digit || unicode.IsDigit(r)
				unique[r] = true
			}
			if len(unique) >= 16 && digit && (lower || upper) {
				pattern = "long key-like run"
				break
			}
		}
	}
	if pattern != "" {
		return "", fmt.Errorf("reason contains what looks like a credential (%s); remove it", pattern)
	}
	return s, nil
}
