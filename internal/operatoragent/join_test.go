package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

type joinFakeHub struct {
	fakeHub
	reads int
}

func (f *joinFakeHub) JoinRequestsList(context.Context) ([]store.JoinRequest, error) {
	f.reads++
	return []store.JoinRequest{{Code: "ABCD-2345", Hostname: "host-b"}}, nil
}
func TestJoinToolReadOnlyAndStrict(t *testing.T) {
	f := &joinFakeHub{}
	s := &Service{Hub: f}
	if _, err := s.Call(context.Background(), "join_requests_list", json.RawMessage(`{}`)); err != nil || f.reads != 1 {
		t.Fatal("read tool", err)
	}
	if _, err := s.Call(context.Background(), "join_requests_list", json.RawMessage(`{"approve":true}`)); err == nil || f.reads != 1 {
		t.Fatal("unknown input accepted")
	}
	found := false
	for _, tool := range Tools() {
		if tool.Name == "join_requests_list" {
			found = true
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint {
				t.Fatal("not read-only")
			}
		}
	}
	if !found {
		t.Fatal("tool missing")
	}
}
