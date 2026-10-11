package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

type fakeScheduleHub struct {
	fakeHub
	callsSchedule int
}

func (f *fakeScheduleHub) ScheduleRead(context.Context, string) (any, error) {
	f.callsSchedule++
	return []store.Schedule{}, nil
}
func (f *fakeScheduleHub) ScheduleManage(context.Context, store.ScheduleRequest, string, bool, string) (store.ScheduleResult, error) {
	f.callsSchedule++
	return store.ScheduleResult{}, nil
}
func (f *fakeScheduleHub) ScheduleRunNow(context.Context, string, string) (any, error) {
	f.callsSchedule++
	return nil, nil
}
func TestScheduleTools(t *testing.T) {
	f := &fakeScheduleHub{}
	s := &Service{Hub: f}
	for _, name := range []string{"schedule_upsert_apply", "schedule_set_enabled_apply"} {
		_, e := s.Call(context.Background(), name, json.RawMessage(`{"idempotency_key":"schedule-key"}`))
		if callErr(t, e).Code != "preview_digest_required" || f.callsSchedule != 0 {
			t.Fatal(e)
		}
	}
	if _, e := s.Call(context.Background(), "schedule_run_now", json.RawMessage(`{"id":"s-1"}`)); e == nil || f.callsSchedule != 0 {
		t.Fatal("manual run missing key called Hub")
	}
	for _, tool := range scheduleTools() {
		if tool.InputSchema["additionalProperties"] != false {
			t.Fatal(tool.Name)
		}
	}
	if _, e := s.Call(context.Background(), "schedule_list", json.RawMessage(`{}`)); e != nil || f.callsSchedule != 1 {
		t.Fatal(e)
	}
	if _, e := s.Call(context.Background(), "schedule_get", json.RawMessage(`{"id":"s-1","unknown":true}`)); e == nil {
		t.Fatal("unknown field")
	}
}
