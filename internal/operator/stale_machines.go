package operator

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

const StaleMachineReviewLimit = 100
const MaxStaleMachineCursorBytes = 2048
const StaleMachineReviewConsistency = "live_candidate_membership"

var ErrInvalidStaleMachineCursor = errors.New("invalid registry review cursor")

// StaleMachineReview is a bounded, live review, never a retirement plan.
// Both limits apply after authorization; hidden identities and counts are omitted.
type StaleMachineReview struct {
	Consistency   string                   `json:"consistency"`
	NextCursor    *string                  `json:"next_cursor"`
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
func (s *Service) ListStaleMachineCandidates(now time.Time, cursor string, canRead func(string) bool) (StaleMachineReview, error) {
	if canRead == nil {
		return StaleMachineReview{}, errors.New("machine read scope required")
	}
	var after MachineReadPosition
	if cursor != "" {
		var err error
		after, err = DecodeStaleMachineCursor(cursor)
		if err != nil {
			return StaleMachineReview{}, err
		}
	}
	evaluatedAt, err := machineEvaluationTime(now)
	if err != nil {
		return StaleMachineReview{}, err
	}
	candidates, err := s.store.StaleMachineCandidates(evaluatedAt)
	if err != nil {
		return StaleMachineReview{}, err
	}
	out := StaleMachineReview{SchemaVersion: 1, Consistency: StaleMachineReviewConsistency, EvaluatedAt: evaluatedAt, Limit: StaleMachineReviewLimit, Items: []StaleMachineReviewItem{}}
	for _, c := range candidates {
		if !canRead(c.MachineID) || (cursor != "" && !staleMachinePositionAfter(c.CreatedAt, c.MachineID, after)) {
			continue
		}
		if len(out.Items) == out.Limit {
			out.Truncated = true
			last := out.Items[len(out.Items)-1]
			next, err := EncodeStaleMachineCursor(MachineReadPosition{CreatedAt: last.CreatedAt, MachineID: last.MachineID})
			if err != nil {
				return StaleMachineReview{}, err
			}
			out.NextCursor = &next
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
		item := StaleMachineReviewItem{MachineID: c.MachineID, DisplayName: name, Hostname: hostname, CreatedAt: c.CreatedAt.UTC(), Branches: c.Branches, DuplicateOf: []string{}}
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

// Cursor keys are immutable registry creation facts, independent of whether the
// anchor is still a candidate. No lookup of the previous page is needed.
type staleMachineCursor struct {
	Version   int       `json:"v"`
	CreatedAt time.Time `json:"created_at"`
	MachineID string    `json:"machine_id"`
}

func staleMachinePositionAfter(created time.Time, id string, after MachineReadPosition) bool {
	return created.After(after.CreatedAt) || (created.Equal(after.CreatedAt) && id > after.MachineID)
}

func EncodeStaleMachineCursor(position MachineReadPosition) (string, error) {
	_, offset := position.CreatedAt.Zone()
	if position.CreatedAt.IsZero() || offset != 0 || validateMachineReadText("cursor machine_id", position.MachineID, 256) != nil {
		return "", ErrInvalidStaleMachineCursor
	}
	var raw bytes.Buffer
	encoder := json.NewEncoder(&raw)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(staleMachineCursor{Version: 1, CreatedAt: position.CreatedAt, MachineID: position.MachineID}); err != nil {
		return "", ErrInvalidStaleMachineCursor
	}
	encoded := base64.RawURLEncoding.EncodeToString(bytes.TrimSuffix(raw.Bytes(), []byte("\n")))
	if len(encoded) > MaxStaleMachineCursorBytes {
		return "", ErrInvalidStaleMachineCursor
	}
	return encoded, nil
}

func DecodeStaleMachineCursor(encoded string) (MachineReadPosition, error) {
	if len(encoded) == 0 || len(encoded) > MaxStaleMachineCursorBytes {
		return MachineReadPosition{}, ErrInvalidStaleMachineCursor
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil {
		return MachineReadPosition{}, ErrInvalidStaleMachineCursor
	}
	var cursor staleMachineCursor
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cursor); err != nil || cursor.Version != 1 {
		return MachineReadPosition{}, ErrInvalidStaleMachineCursor
	}
	position := MachineReadPosition{CreatedAt: cursor.CreatedAt, MachineID: cursor.MachineID}
	canonical, err := EncodeStaleMachineCursor(position)
	// Canonical equality also rejects duplicate/aliased/missing fields, trailing
	// documents, noncanonical timestamps, whitespace and alternate base64 forms.
	if err != nil || canonical != encoded {
		return MachineReadPosition{}, ErrInvalidStaleMachineCursor
	}
	return position, nil
}

// ParseStaleMachineReviewQuery is shared by the HTML and JSON read adapters.
func ParseStaleMachineReviewQuery(rawQuery string, forceQuery bool) (string, error) {
	if len(rawQuery) > 3*MaxStaleMachineCursorBytes+7 || (forceQuery && rawQuery == "") {
		return "", ErrInvalidStaleMachineCursor
	}
	if rawQuery == "" {
		return "", nil
	}
	values, err := url.ParseQuery(rawQuery)
	if err != nil || len(values) != 1 || len(values["cursor"]) != 1 {
		return "", ErrInvalidStaleMachineCursor
	}
	cursor := values.Get("cursor")
	if _, err := DecodeStaleMachineCursor(cursor); err != nil {
		return "", err
	}
	return cursor, nil
}
