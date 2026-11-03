package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
	"testing"
)

type profileFakeHub struct {
	fakeHub
	profile store.FleetHostProfile
}

func (f *profileFakeHub) HostProfile(context.Context) (store.FleetHostProfile, error) {
	f.call("profile")
	return f.profile, nil
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

func TestHostProfileMetadataForwarded(t *testing.T) {
	f := &profileFakeHub{profile: store.FleetHostProfile{Hosts: []store.HostProfileStatus{{Result: &model.HostApplyResult{MachineType: "server", ProfileSource: "default:server"}}}}}
	s := &Service{Hub: f}
	out, err := s.Call(context.Background(), "host_profile_get", json.RawMessage(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out)
	if err != nil || !strings.Contains(string(raw), `"machine_type":"server"`) || !strings.Contains(string(raw), `"profile_source":"default:server"`) {
		t.Fatal(string(raw), err)
	}
}
