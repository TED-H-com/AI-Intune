package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

type profileFakeHub struct{ fakeHub }

func (f *profileFakeHub) HostProfile(context.Context) (store.FleetHostProfile, error) {
	f.call("profile")
	return store.FleetHostProfile{}, nil
}
func TestHostProfileReadTool(t *testing.T) {
	f := &profileFakeHub{}
	s := &Service{Hub: f}
	if _, err := s.Call(context.Background(), "host_profile_get", json.RawMessage(`{"command":"x"}`)); err == nil {
		t.Fatal("unknown argument accepted")
	}
	if len(f.calls) != 0 {
		t.Fatal("invalid called Hub")
	}
	if _, err := s.Call(context.Background(), "host_profile_get", json.RawMessage(`{}`)); err != nil || !f.called("profile") {
		t.Fatal(err)
	}
	for _, tool := range Tools() {
		if tool.Name == "host_profile_get" {
			if !tool.Annotations.ReadOnlyHint {
				t.Fatal("not readonly")
			}
			return
		}
	}
	t.Fatal("missing tool")
}
