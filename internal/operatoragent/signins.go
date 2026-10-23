package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
)

type signinHub interface {
	Signins(context.Context) ([]store.SigninGroup, error)
}

func (s *Service) signinsList(ctx context.Context, raw json.RawMessage) (any, error) {
	if e := decodeEmpty(raw); e != nil {
		return nil, e
	}
	h, ok := s.Hub.(signinHub)
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "sign-ins client unavailable"}
	}
	v, e := h.Signins(ctx)
	return v, hubErr(e)
}
