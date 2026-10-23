package operatoragent

import (
	"context"
	"encoding/json"

	"github.com/teddashh/AI-Intune/internal/store"
)

func (s *Service) machineReadiness(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		MachineID string `json:"machine_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if err := requireID("machine_id", args.MachineID); err != nil {
		return nil, err
	}
	h, ok := s.Hub.(interface {
		MachineReadiness(context.Context, string) (store.HostChecklist, error)
	})
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "Readiness client unavailable"}
	}
	result, err := h.MachineReadiness(ctx, args.MachineID)
	return result, hubErr(err)
}
