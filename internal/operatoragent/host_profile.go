package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
)

func (s *Service) hostProfileGet(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct{}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	h, ok := s.Hub.(interface {
		HostProfile(context.Context) (store.FleetHostProfile, error)
	})
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "Host setup client unavailable"}
	}
	out, err := h.HostProfile(ctx)
	return out, hubErr(err)
}
