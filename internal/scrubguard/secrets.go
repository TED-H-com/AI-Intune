package scrubguard

import (
	"math"
	"regexp"
	"sort"
)

// RedactionMarker replaces suspected credentials. Counts describe matched spans,
// not unique credentials. This heuristic is not a guarantee of secret absence.
const RedactionMarker = "[REDACTED]"

const (
	FlagAssignment     = "credential_assignment"
	FlagAuthorization  = "authorization"
	FlagEntropy        = "high_entropy"
	FlagJWT            = "jwt"
	FlagPEM            = "pem_private_key"
	FlagProviderToken  = "provider_token"
	FlagURLCredentials = "url_credentials"
)

type secretPattern struct {
	flag    string
	pattern *regexp.Regexp
}

var secretPatterns = []secretPattern{
	{FlagPEM, regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----.*?(?:-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----|$)`)},
	{FlagAuthorization, regexp.MustCompile(`(?i)(?:authorization\s*[:=]\s*(?:bearer|basic)?\s*|bearer\s+)[^\s,;"'<>]+`)},
	{FlagAssignment, regexp.MustCompile(`(?i)["']?\b(?:(?:[a-z0-9]+[_-])*(?:access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|api[_-]?key|access[_-]?key|secret[_-]?key|client[_-]?secret|private[_-]?key|token|password|passwd|secret))["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;<>]+)`)},
	{FlagURLCredentials, regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/@]+:[^\s/@]*@[^\s<>"']*`)},
	{FlagProviderToken, regexp.MustCompile(`(?:sk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{8,}|sk_(?:live|test)_[A-Za-z0-9]{8,}|rk_(?:live|test)_[A-Za-z0-9]{8,}|whsec_[A-Za-z0-9]{8,}|(?:gh[pousr]_|github_pat_|glpat-|xox[baprs]-|AIza|AKIA|ASIA|npm_|hf_|pypi-)[A-Za-z0-9_-]{8,})`)},
	{FlagJWT, regexp.MustCompile(`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`)},
}
var entropyPattern = regexp.MustCompile(`[A-Za-z0-9_+/=.-]{20,}`)
var hexadecimalDigestPattern = regexp.MustCompile(`(?i)^(?:[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128})$`)

// Result describes one scrub pass. Flags are sorted, unique heuristic classes;
// Count is the number of replaced spans, not a count of unique credentials.
type Result struct {
	Value string
	Count int
	Flags []string
}

// ScrubWithResult redacts known credential shapes and tokens of at least 20
// bytes whose Shannon entropy is >= 4 bits/byte. Long path components can be
// false positives; ordinary paths, UUIDs and hexadecimal hashes are retained.
func ScrubWithResult(value string) Result {
	result := Result{Value: value}
	flags := map[string]struct{}{}
	for _, candidate := range secretPatterns {
		result.Value = candidate.pattern.ReplaceAllStringFunc(result.Value, func(string) string {
			result.Count++
			flags[candidate.flag] = struct{}{}
			return RedactionMarker
		})
	}
	result.Value = entropyPattern.ReplaceAllStringFunc(result.Value, func(token string) string {
		if hexadecimalDigestPattern.MatchString(token) {
			return token
		}
		frequencies := map[byte]int{}
		for i := 0; i < len(token); i++ {
			frequencies[token[i]]++
		}
		entropy := 0.0
		for _, n := range frequencies {
			p := float64(n) / float64(len(token))
			entropy -= p * math.Log2(p)
		}
		if entropy >= 4 {
			result.Count++
			flags[FlagEntropy] = struct{}{}
			return RedactionMarker
		}
		return token
	})
	for flag := range flags {
		result.Flags = append(result.Flags, flag)
	}
	sort.Strings(result.Flags)
	return result
}

// Scrub is the compact compatibility form for callers that only need text and
// a replacement count.
func Scrub(value string) (string, int) {
	result := ScrubWithResult(value)
	return result.Value, result.Count
}
