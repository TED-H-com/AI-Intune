package operator

import (
	"errors"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

const StaleMachineReviewLimit = 100

// StaleMachineReview is a bounded, live review, never a retirement plan.
// Both limits apply after authorization; hidden identities and counts are omitted.
type StaleMachineReview struct {
	SchemaVersion int                      `json:"schema_version"`
	EvaluatedAt   time.Time                `json:"evaluated_at"`
	Limit         int                      `json:"limit"`
	Truncated     bool                     `json:"truncated"`
	Items         []StaleMachineReviewItem `json:"items"`
}

type StaleMachineReviewItem struct {
	MachineID        string                     `json:"machine_id"`
	DisplayName      string                     `json:"display_name"`
	Hostname         string                     `json:"hostname"`
	CreatedAt        time.Time                  `json:"created_at"`
	Branches         []store.StaleMachineBranch `json:"branches"`
	DuplicateOf      []string                   `json:"duplicate_of"`
	RelatedTruncated bool                       `json:"related_truncated"`
}

// ListStaleMachineCandidates uses the existing store snapshot without changing
// eligibility. Adapters supply their authenticated read scope for every identity,
// including references. nil is fail-closed. Names are display evidence only.
func (s *Service) ListStaleMachineCandidates(now time.Time, canRead func(string) bool) (StaleMachineReview, error) {
	if canRead == nil {
		return StaleMachineReview{}, errors.New("machine read scope required")
	}
	evaluatedAt, err := machineEvaluationTime(now)
	if err != nil {
		return StaleMachineReview{}, err
	}
	candidates, err := s.store.StaleMachineCandidates(evaluatedAt)
	if err != nil {
		return StaleMachineReview{}, err
	}
	out := StaleMachineReview{SchemaVersion: 1, EvaluatedAt: evaluatedAt, Limit: StaleMachineReviewLimit, Items: []StaleMachineReviewItem{}}
	for _, c := range candidates {
		if !canRead(c.MachineID) {
			continue
		}
		if len(out.Items) == out.Limit {
			out.Truncated = true
			break
		}
		if err := validateMachineReadText("machine_id", c.MachineID, 256); err != nil {
			return StaleMachineReview{}, err
		}
		name, _ := safeMachineDisplayName(c.DisplayName)
		hostname := ""
		if c.Hostname != "" {
			hostname, _ = safeMachineDisplayName(c.Hostname)
		}
		item := StaleMachineReviewItem{MachineID: c.MachineID, DisplayName: name, Hostname: hostname, CreatedAt: c.CreatedAt, Branches: c.Branches, DuplicateOf: []string{}}
		for _, id := range c.DuplicateOf {
			if !canRead(id) {
				continue
			}
			if len(item.DuplicateOf) == StaleMachineReviewLimit {
				item.RelatedTruncated = true
				break
			}
			if err := validateMachineReadText("related machine_id", id, 256); err != nil {
				return StaleMachineReview{}, err
			}
			item.DuplicateOf = append(item.DuplicateOf, id)
		}
		out.Items = append(out.Items, item)
	}
	return out, nil
}
