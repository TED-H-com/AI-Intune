package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
)

func (s *Service) machineDisks(ctx context.Context, raw json.RawMessage) (any, error) {
	var args struct {
		MachineID string `json:"machine_id"`
	}
	if err := decodeArgs(raw, &args); err != nil {
		return nil, err
	}
	if args.MachineID == "" || len(args.MachineID) > 256 {
		return nil, &CallError{Code: "invalid_arguments", Message: "machine_id is required"}
	}
	h, ok := s.Hub.(interface {
		MachineDisks(context.Context, string) (store.MachineDisks, error)
	})
	if !ok {
		return nil, &CallError{Code: "not_configured", Message: "Disk inventory client unavailable"}
	}
	out, err := h.MachineDisks(ctx, args.MachineID)
	return out, hubErr(err)
}
