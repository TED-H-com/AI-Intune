package operatoragent

import (
	"context"
	"encoding/json"

	"github.com/teddashh/AI-Intune/internal/store"
)

func (s *Service) joinRequestsList(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	h, ok := s.Hub.(interface {
		JoinRequestsList(context.Context) ([]store.JoinRequest, error)
	})
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "Waiting machines client unavailable"}
	}
	out, err := h.JoinRequestsList(ctx)
	return out, hubErr(err)
}
