package operatoragent

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/teddashh/AI-Intune/internal/store"
)

type readinessFakeHub struct{ fakeHub }

func (f *readinessFakeHub) MachineReadiness(context.Context, string) (store.HostChecklist, error) {
	f.call("readiness")
	return store.HostChecklist{}, nil
}
func TestMachineReadinessTool(t *testing.T) {
	f := &readinessFakeHub{}
	s := &Service{Hub: f}
	for _, raw := range []string{`{}`, `{"machine_id":"example","raw":true}`} {
		if _, err := s.Call(context.Background(), "machine_readiness", json.RawMessage(raw)); err == nil {
			t.Fatal("accepted invalid args")
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid input called Hub")
	}
	if _, err := s.Call(context.Background(), "machine_readiness", json.RawMessage(`{"machine_id":"example"}`)); err != nil || !f.called("readiness") {
		t.Fatalf("read: %v", err)
	}
	for _, tool := range Tools() {
		if tool.Name == "machine_readiness" {
			if !tool.Annotations.ReadOnlyHint {
				t.Fatal("missing readonly hint")
			}
			return
		}
	}
	t.Fatal("tool missing")
}
