package operatoragent

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

type fakeSigninHub struct {
	fakeHub
	calls int
}

func (f *fakeSigninHub) Signins(context.Context) ([]store.SigninGroup, error) {
	f.calls++
	return []store.SigninGroup{{CLI: "codex", Slot: 1}}, nil
}
func TestSigninsListReadOnly(t *testing.T) {
	f := &fakeSigninHub{}
	s := &Service{Hub: f}
	v, e := s.Call(context.Background(), "signins_list", json.RawMessage(`{}`))
	if e != nil || v == nil || f.calls != 1 {
		t.Fatal(v, e)
	}
	if _, e = s.Call(context.Background(), "signins_list", json.RawMessage(`{"code":"never"}`)); e == nil {
		t.Fatal("unknown argument accepted")
	}
	for _, tool := range Tools() {
		if tool.Name == "signins_start" {
			t.Fatal("MCP write tool")
		}
	}
}
