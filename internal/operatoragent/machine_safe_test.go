package operatoragent

import (
	"context"
	"encoding/json"
	"testing"
)

func TestMachineSafeDetailTool(t *testing.T) {
	f := &fakeHub{}
	s := &Service{Hub: f}
	for _, raw := range []string{`{}`, `{"machine_id":"example","raw":true}`} {
		if _, err := s.Call(context.Background(), "machine_safe_detail", json.RawMessage(raw)); err == nil {
			t.Fatal("accepted invalid args")
		}
	}
	if f.called("MachineSafe") {
		t.Fatal("invalid input called Hub")
	}
	if _, err := s.Call(context.Background(), "machine_safe_detail", json.RawMessage(`{"machine_id":"example"}`)); err != nil || !f.called("MachineSafe") {
		t.Fatalf("read: %v", err)
	}
	for _, tool := range Tools() {
		if tool.Name == "machine_safe_detail" {
			if !tool.Annotations.ReadOnlyHint {
				t.Fatal("missing read-only hint")
			}
			return
		}
	}
	t.Fatal("tool missing")
}
