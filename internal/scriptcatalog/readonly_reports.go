package scriptcatalog

import (
	"encoding/json"
	"regexp"
)

// IsReadReport identifies the reviewed Python reports and their output contract.
func IsReadReport(id string) bool {
	return id == "oci-cost-report-v1" || id == "network-watch-v1" || id == "bat-release-check-v1"
}

func ociCostSchema() Schema {
	lo, hi := 0, 1000000
	return Schema{Type: "object", Required: []string{"profile"}, Properties: map[string]Property{
		"profile":    {Type: "string", Pattern: "^[a-z0-9-]{1,32}$", MinLength: 1, MaxLength: 32},
		"warn_usd":   {Type: "number", Minimum: &lo, Maximum: &hi},
		"urgent_usd": {Type: "number", Minimum: &lo, Maximum: &hi},
	}}
}

func networkWatchSchema() Schema {
	host := &Property{Type: "string", Pattern: "^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$", MinLength: 1, MaxLength: 253}
	return Schema{Type: "object", Properties: map[string]Property{
		"expected_peers":         {Type: "array", MaxItems: 32, Items: host},
		"resolve":                {Type: "array", MaxItems: 8, Items: host},
		"mode":                   {Type: "string", Enum: []string{"watch", "daily"}, MinLength: 5, MaxLength: 5},
		"baseline_listen_digest": {Type: "string", Pattern: "^[a-f0-9]{64}$", MinLength: 64, MaxLength: 64},
		// Strings fit the catalog's closed string-array schema; ports stay bounded.
		"baseline_listen_ports": {Type: "array", MaxItems: 256, Items: &Property{Type: "string", Pattern: "^([1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$", MinLength: 1, MaxLength: 5}},
	}}
}

var listenDigest = regexp.MustCompile(`^[a-f0-9]{64}$`)
var reportIdentity = regexp.MustCompile(`(?i)(ocid1\.[a-z0-9.-]+|[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,})`)

// RedactReadReportJSON preserves only the network report's validated digest in
// metrics. Both agent and Hub use it: generic secret redaction masks hex digests.
func RedactReadReportJSON(id string, raw []byte) string {
	var report map[string]any
	if !IsReadReport(id) || len(raw) > 64<<10 || json.Unmarshal(raw, &report) != nil || report == nil {
		return ""
	}
	var clean func(any, string) any
	clean = func(value any, path string) any {
		switch v := value.(type) {
		case string:
			return reportIdentity.ReplaceAllString(Redact(v), "[REDACTED]")
		case map[string]any:
			out := make(map[string]any, len(v))
			for key, item := range v {
				safeKey := reportIdentity.ReplaceAllString(Redact(key), "[REDACTED]")
				if digest, ok := item.(string); ok && path == "metrics" && key == "listen_digest" && id == "network-watch-v1" && listenDigest.MatchString(digest) {
					out[safeKey] = digest
				} else {
					next := "other"
					if path == "" && key == "metrics" {
						next = "metrics"
					}
					out[safeKey] = clean(item, next)
				}
			}
			return out
		case []any:
			for i := range v {
				v[i] = clean(v[i], "other")
			}
			return v
		default:
			return v
		}
	}
	encoded, err := json.Marshal(clean(report, ""))
	if err != nil || len(encoded) > 64<<10 {
		return ""
	}
	return string(encoded)
}
