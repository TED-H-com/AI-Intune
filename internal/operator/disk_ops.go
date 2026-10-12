package operator

import (
	"github.com/teddashh/AI-Intune/internal/store"
	"time"
)

func (s *Service) DiskPolicies() ([]store.OpsPolicy, error)      { return s.store.DiskPolicies() }
func (s *Service) DiskPolicy(id string) (store.OpsPolicy, error) { return s.store.DiskPolicy(id) }
func (s *Service) DiskPolicyUpsert(req store.DiskPolicyRequest, apply bool, key string, actor Actor) (store.DiskPolicyResult, error) {
	return s.store.DiskPolicyUpsert(req, apply, key, auditFromActor(actor))
}
func (s *Service) DiskOpsApprovals(now time.Time) ([]store.OpsApproval, error) {
	return s.store.OpsApprovals(now)
}

// Approval creation is reserved for reviewed operation adapters.
func (s *Service) CreateDiskOpsApproval(binding store.OpsApproval, actor Actor) (store.OpsApproval, error) {
	return s.store.CreateOpsApproval(binding, auditFromActor(actor))
}
func (s *Service) DecideDiskOpsApproval(binding store.OpsApproval, approve bool, actor Actor) (store.OpsApproval, error) {
	return s.store.DecideOpsApproval(binding, approve, auditFromActor(actor))
}

func (s *Service) DiskOpsWritesEnabled() bool { return s.store.DiskOpsWritesEnabled() }
func (s *Service) DiskPolicyRevision(id string, revision int64) (store.OpsPolicy, error) {
	return s.store.DiskPolicyRevision(id, revision)
}
func (s *Service) DiskOpsApprovalsFiltered(state, machine, operation string, now time.Time) ([]store.OpsApproval, error) {
	return s.store.OpsApprovalsFiltered(state, machine, operation, now)
}
func (s *Service) DiskOpsApprovalDecision(req store.OpsApprovalDecisionRequest, apply bool, key string, actor Actor) (store.OpsApprovalDecisionResult, error) {
	return s.store.OpsApprovalDecision(req, apply, key, auditFromActor(actor))
}
func (s *Service) ReauthenticateDiskAdmin(actor Actor, password, code string, requireMFA bool) error {
	return s.store.ReauthenticateDiskAdmin(auditFromActor(actor), password, code, requireMFA)
}
func (s *Service) RecordDiskOpsTransportRejection(actor Actor, subject string, policy bool) error {
	a := auditFromActor(actor)
	a.Action = store.AuditOpsApproval
	if policy {
		a.Action = store.AuditDiskPolicyApply
	}
	a.Subject = subject
	a.OK = false
	a.Detail = store.OperatorTransportRejectionPrefix + "disk operation form or reauthentication rejected"
	return s.store.RecordAudit(a)
}

func (s *Service) DiskOpsStatus(id string) (store.DiskOpsStatus, error) {
	return s.store.DiskOpsStatus(id)
}
func (s *Service) DiskSchedules() ([]store.Schedule, error)       { return s.store.ScheduleList() }
func (s *Service) DiskSchedule(id string) (store.Schedule, error) { return s.store.ScheduleGet(id) }
func (s *Service) DiskScheduleRunNow(id, digest, key string, apply bool, actor Actor) (store.ScheduleResult, error) {
	return s.store.DiskScheduleRunNow(id, digest, key, apply, auditFromActor(actor))
}
