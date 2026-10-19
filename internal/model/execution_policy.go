package model

import "errors"

const ExecutionManaged = "managed"
const ExecutionMonitorOnly = "monitor_only"

// ExecutionPolicy is Hub authority, never an agent health claim.
type ExecutionPolicy struct {
	Mode     string `json:"mode"`
	Revision int64  `json:"revision"`
}

func (p ExecutionPolicy) Validate() error {
	if (p.Mode != ExecutionManaged && p.Mode != ExecutionMonitorOnly) || p.Revision < 1 {
		return errors.New("invalid machine execution policy")
	}
	return nil
}
