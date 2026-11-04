package operatoragent

import (
	"bytes"
	"context"
	"encoding/json"

	"github.com/teddashh/AI-Intune/internal/operator"
)

func (s *Service) staleMachinesList(ctx context.Context, raw json.RawMessage) (any, error) {
	if trimmed := bytes.TrimSpace(raw); len(trimmed) > 0 && trimmed[0] != '{' {
		return nil, &CallError{Code: "invalid_arguments", Message: "arguments must be an object"}
	}
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	h, ok := s.Hub.(interface {
		StaleMachineCandidates(context.Context) (operator.StaleMachineReview, error)
	})
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "Registry review client unavailable"}
	}
	result, err := h.StaleMachineCandidates(ctx)
	return result, hubErr(err)
}
