package operatoragent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/teddashh/AI-Intune/internal/operator"
)

func (s *Service) staleMachinesList(ctx context.Context, raw json.RawMessage) (any, error) {
	cursor, err := decodeStaleMachineArgs(raw)
	if err != nil {
		return nil, err
	}
	h, ok := s.Hub.(interface {
		StaleMachineCandidates(context.Context, string) (operator.StaleMachineReview, error)
	})
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "Registry review client unavailable"}
	}
	result, err := h.StaleMachineCandidates(ctx, cursor)
	return result, hubErr(err)
}

func decodeStaleMachineArgs(raw json.RawMessage) (string, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		raw = json.RawMessage(`{}`)
	}
	invalid := &CallError{Code: "invalid_arguments", Message: "expected an object with an optional registry review cursor"}
	if len(raw) > 6*operator.MaxStaleMachineCursorBytes+32 {
		return "", invalid
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	token, err := dec.Token()
	if err != nil || token != json.Delim('{') {
		return "", invalid
	}
	cursor, seen := "", false
	for dec.More() {
		key, err := dec.Token()
		if err != nil || seen {
			return "", invalid
		}
		if key != "cursor" {
			return "", &CallError{Code: "invalid_arguments", Message: fmt.Sprintf("unknown field %q; allowed fields: cursor", key)}
		}
		seen = true
		if err := dec.Decode(&cursor); err != nil {
			return "", invalid
		}
		if _, err := operator.DecodeStaleMachineCursor(cursor); err != nil {
			return "", invalid
		}
	}
	if token, err := dec.Token(); err != nil || token != json.Delim('}') {
		return "", invalid
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", invalid
	}
	return cursor, nil
}
