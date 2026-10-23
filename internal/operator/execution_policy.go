package operator

import "github.com/teddashh/AI-Intune/internal/store"

func (s *Service) MachineExecutionPolicy(machine string) (store.MachineExecutionPolicy, error) {
	return s.store.MachineExecutionPolicy(machine)
}
func (s *Service) ManageExecutionPolicy(req store.ExecutionPolicyRequest, actor Actor, apply bool) (store.ExecutionPolicyResult, error) {
	req.Audit = auditFromActor(actor)
	out, err := s.store.ManageExecutionPolicy(req, apply)
	s.endClosedTerminalSessions(err, out.ClosedSessions)
	return out, err
}
