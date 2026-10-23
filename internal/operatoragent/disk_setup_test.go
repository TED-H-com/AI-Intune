package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

type disksFakeHub struct{ fakeHub }

func (f *disksFakeHub) MachineDisks(context.Context, string) (store.MachineDisks, error) {
	f.call("disks")
	return store.MachineDisks{}, nil
}
func TestMachineDisksReadOnlyTool(t *testing.T) {
	f := &disksFakeHub{}
	s := &Service{Hub: f}
	for _, raw := range []string{`{}`, `{"machine_id":"example","force":true}`} {
		if _, err := s.Call(context.Background(), "machine_disks", json.RawMessage(raw)); err == nil {
			t.Fatal(raw)
		}
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid request called hub")
	}
	if _, err := s.Call(context.Background(), "machine_disks", json.RawMessage(`{"machine_id":"example"}`)); err != nil || !f.called("disks") {
		t.Fatal(err)
	}
	for _, tool := range Tools() {
		if tool.Name == "machine_disks" {
			if !tool.Annotations.ReadOnlyHint {
				t.Fatal("not read-only")
			}
			return
		}
	}
	t.Fatal("missing tool")
}
