package operator

import "github.com/teddashh/AI-Intune/internal/store"

func (s *Service) ScriptRun(req store.ScriptRunRequest, apply bool, key string, actor Actor) (store.ScriptRunResult, error) {
	return s.store.ScriptRun(req, apply, key, auditFromActor(actor))
}

func (s *Service) ScheduleManage(req store.ScheduleRequest, op string, apply bool, key string, actor Actor) (store.ScheduleResult, error) {
	return s.store.ScheduleManage(req, op, apply, key, auditFromActor(actor))
}
func (s *Service) ScheduleRunNow(id, key string, actor Actor) (store.ScheduleRunNowResponse, error) {
	return s.store.ScheduleRunNow(id, key, auditFromActor(actor))
}

func (s *Service) RejectScheduleRunNow(id, key string, actor Actor) error {
	a := auditFromActor(actor)
	a.Action = store.AuditScheduleRunNow
	a.Subject = id
	a.IdempotencyKey = key
	a.OK = false
	a.Detail = "schedule not found"
	return s.store.RecordAudit(a)
}

func (s *Service) Schedules() ([]store.Schedule, error)       { return s.store.ScheduleList() }
func (s *Service) Schedule(id string) (store.Schedule, error) { return s.store.ScheduleGet(id) }
func (s *Service) ScheduleJobIDs(id string) ([]string, error) { return s.store.ScheduleJobIDs(id) }
func (s *Service) RejectScheduleTransport(actor Actor, action store.AuditAction) error {
	a := auditFromActor(actor)
	a.Action = action
	a.OK = false
	a.Detail = "invalid schedule form"
	return s.store.RecordAudit(a)
}
