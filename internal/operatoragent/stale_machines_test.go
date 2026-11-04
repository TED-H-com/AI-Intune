package operatoragent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
)

type staleReviewHub struct {
	fakeHub
	cursor string
}

func (h *staleReviewHub) StaleMachineCandidates(_ context.Context, cursor string) (operator.StaleMachineReview, error) {
	h.cursor = cursor
	h.call("StaleMachineCandidates")
	return operator.StaleMachineReview{SchemaVersion: 1, Limit: 100, Items: []operator.StaleMachineReviewItem{}}, h.err
}
func TestStaleMachinesToolReadContract(t *testing.T) {
	h := &staleReviewHub{}
	s := &Service{Hub: h}
	for _, raw := range []string{`{"limit":1}`, `{"retire":true}`, `null`, `[]`, `{} {}`, `{"cursor":null}`, `{"cursor":""}`, `{"Cursor":"bad"}`, `{"cursor":"bad"}`} {
		if _, err := s.Call(context.Background(), "stale_machines_list", json.RawMessage(raw)); err == nil {
			t.Fatalf("accepted %s", raw)
		}
	}
	if len(h.calls) != 0 {
		t.Fatal("invalid args called Hub")
	}
	if _, err := s.Call(context.Background(), "stale_machines_list", json.RawMessage(`{}`)); err != nil || len(h.calls) != 1 {
		t.Fatalf("read %v", err)
	}
	cursor, err := operator.EncodeStaleMachineCursor(operator.MachineReadPosition{CreatedAt: time.Now().UTC().Add(-24 * time.Hour), MachineID: "anchor"})
	if err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]string{"cursor": cursor})
	if _, err := s.Call(context.Background(), "stale_machines_list", args); err != nil || h.cursor != cursor {
		t.Fatalf("cursor not forwarded: %s %v", h.cursor, err)
	}
	duplicate := `{"cursor":"` + cursor + `","cursor":"` + cursor + `"}`
	before := len(h.calls)
	if _, err := s.Call(context.Background(), "stale_machines_list", json.RawMessage(duplicate)); err == nil || len(h.calls) != before {
		t.Fatal("duplicate cursor reached Hub")
	}
	h.err = errors.New("forbidden")
	if _, err := s.Call(context.Background(), "stale_machines_list", json.RawMessage(`{}`)); err == nil {
		t.Fatal("hidden Hub failure")
	}
	h.err = nil
	found := false
	for _, tool := range Tools() {
		if tool.Name == "stale_machines_list" {
			found = true
			if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint || tool.Annotations.DestructiveHint {
				t.Fatal("unsafe annotations")
			}
		}
	}
	if !found {
		t.Fatal("tool not listed")
	}
	var output bytes.Buffer
	input := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"stale_machines_list","arguments":{}}}` + "\n"
	if err := Serve(context.Background(), strings.NewReader(input), &output, s); err != nil || !strings.Contains(output.String(), `"isError":false`) {
		t.Fatalf("MCP %v %s", err, output.String())
	}
}
