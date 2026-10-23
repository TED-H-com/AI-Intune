package operator

import (
	"bytes"
	"encoding/json"
	"sort"
	"time"

	"github.com/teddashh/AI-Intune/internal/scrubguard"
)

// MachineSafeResult is a detached JSON projection: no source-only fields or
// access coordinates can escape through a future exported Go field.
type MachineSafeResult struct {
	SchemaVersion   int      `json:"schema_version"`
	Projection      any      `json:"projection"`
	Redactions      int      `json:"redactions"`
	Redacted        bool     `json:"redacted"`
	RedactionFlags  []string `json:"redaction_flags"`
	ScrubberVersion int      `json:"scrubber_version"`
}

func (s *Service) MachineSafe(id string, now time.Time) (MachineSafeResult, error) {
	detail, err := s.MachineDetail(id, now)
	if err != nil {
		return MachineSafeResult{}, err
	}
	evidence, err := s.MachineEvidence(MachineEvidenceRequest{MachineID: id}, now)
	if err != nil {
		return MachineSafeResult{}, err
	}
	return scrubMachineProjection(map[string]any{"detail": detail, "evidence": evidence})
}

func scrubMachineProjection(source any) (MachineSafeResult, error) {
	raw, err := json.Marshal(source)
	if err != nil {
		return MachineSafeResult{}, err
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err = decoder.Decode(&value); err != nil {
		return MachineSafeResult{}, err
	}
	count := 0
	flags := map[string]struct{}{}
	var walk func(any) any
	walk = func(v any) any {
		switch x := v.(type) {
		case string:
			result := scrubguard.ScrubWithResult(x)
			count += result.Count
			for _, flag := range result.Flags {
				flags[flag] = struct{}{}
			}
			return result.Value
		case []any:
			for i := range x {
				x[i] = walk(x[i])
			}
		case map[string]any:
			for key, item := range x {
				x[key] = walk(item)
			}
		}
		return v
	}
	value = walk(value)
	redactionFlags := make([]string, 0, len(flags))
	for flag := range flags {
		redactionFlags = append(redactionFlags, flag)
	}
	sort.Strings(redactionFlags)
	return MachineSafeResult{SchemaVersion: 1, Projection: value, Redactions: count, Redacted: count > 0, RedactionFlags: redactionFlags, ScrubberVersion: 1}, nil
}
