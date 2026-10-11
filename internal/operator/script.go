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
