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

// DiskActionPreview creates only a pending human decision and redacted evidence.
// Mutation dispatch uses DiskActionDecide, never a generic script apply.
func (s *Service) DiskActionPreview(req store.DiskActionRequest, actor Actor) (store.DiskActionPreview, error) {
	return s.store.DiskActionPreview(req, auditFromActor(actor))
}

// DiskActionDecide is the dedicated exact action boundary. Approval consumption
// and job creation are atomic; generic script applies cannot dispatch it.
func (s *Service) DiskActionDecide(req store.OpsApprovalDecisionRequest, apply bool, key string, actor Actor) (store.OpsApprovalDecisionResult, error) {
	return s.store.DiskActionDecide(req, apply, key, auditFromActor(actor))
}

func (s *Service) DiskQuarantineList(machine string) ([]store.DiskQuarantineItem, error) {
	return s.store.DiskQuarantineList(machine)
}
func (s *Service) DiskRestorePreview(req store.DiskRestoreRequest, actor Actor) (store.DiskActionPreview, error) {
	return s.store.DiskRestorePreview(req, auditFromActor(actor))
}
func (s *Service) DiskManifestHuman(id string, actor Actor) (store.DiskManifest, error) {
	return s.store.DiskManifestHuman(id, auditFromActor(actor))
}

func (s *Service) DiskReportDecisions(id string) (map[string]string, error) {
	return s.store.DiskReportDecisions(id)
}

func (s *Service) DiskRestoreApply(req store.OpsApprovalDecisionRequest, apply bool, key string, actor Actor) (store.OpsApprovalDecisionResult, error) {
	return s.store.DiskRestoreApply(req, apply, key, auditFromActor(actor))
}

func (s *Service) DiskOwnershipGet(machine, scope string) (store.DiskOwnership, error) {
	return s.store.DiskOwnershipGet(machine, scope)
}
func (s *Service) DiskOwnershipManage(req store.DiskOwnershipRequest, apply bool, key string, actor Actor) (store.DiskOwnershipResult, error) {
	return s.store.DiskOwnershipManage(req, apply, key, auditFromActor(actor))
}
func (s *Service) DiskAlertsList(machine string) ([]store.DiskAlert, error) {
	return s.store.DiskAlertsList(machine)
}

func (s *Service) DiskCanaryGet(machine, scope string) (store.DiskCanary, error) {
	return s.store.DiskCanaryGet(machine, scope, time.Now().UTC())
}

func (s *Service) DiskAlertAcknowledge(req store.DiskAlertAckRequest, apply bool, key string, actor Actor) (store.DiskAlertAckResult, error) {
	return s.store.DiskAlertAcknowledge(req, apply, key, auditFromActor(actor))
}

func (s *Service) DiskSupervision(machine string) (store.DiskSupervision, error) {
	return s.store.DiskSupervision(machine)
}

func (s *Service) DiskAlertsPageAfter(after string) (store.DiskAlertsPage, error) {
	return s.store.DiskAlertsPageAfter(after)
}
func (s *Service) DiskAlertMountLabels(machines []string) (map[string][]store.DiskMountUsage, error) {
	return s.store.DiskAlertMountLabels(machines)
}

func (s *Service) DiskAlertBannerCounts() (store.DiskAlertBannerCounts, error) {
	return s.store.DiskAlertBannerCounts()
}
