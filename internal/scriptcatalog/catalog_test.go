package scriptcatalog

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestRegistryHashIntegrity(t *testing.T) {
	if len(List()) != 13 {
		t.Fatal("expected two probes, BAT, disk-safe/deep, four approved actions and three read reports")
	}
	for _, meta := range List() {
		e, ok := Lookup(meta.ID)
		if !ok || Digest(e.Bytes) != e.SHA256 {
			t.Fatal("embedded hash mismatch")
		}
		if ((e.ID == "bat-sweep-report-v1" || e.ID == "disk-safe-clean-v2" || IsDiskAction(e.ID)) && e.Mode != "write") || (e.ID != "bat-sweep-report-v1" && e.ID != "disk-safe-clean-v2" && !IsDiskAction(e.ID) && e.Mode != "read") || e.RunsAs != "agent-user" || e.ArgsSchema.AdditionalProperties {
			t.Fatal("unsafe catalog metadata")
		}
	}
	e, _ := Lookup("fleet-probe-v1")
	e.Bytes[0] = 'x'
	unchanged, _ := Lookup(e.ID)
	if Digest(unchanged.Bytes) != unchanged.SHA256 {
		t.Fatal("registry is mutable")
	}
}
func TestArgsValidation(t *testing.T) {
	min, max := 1, 5
	e := Entry{ArgsSchema: Schema{Type: "object", Properties: map[string]Property{"mode": {Type: "string", Enum: []string{"facts"}, MaxLength: 8}, "label": {Type: "string", Pattern: "^[a-z]+$", MaxLength: 8}, "count": {Type: "integer", Minimum: &min, Maximum: &max}}}}
	for _, raw := range []string{`{"unknown":1}`, `{"mode":"bad"}`, `{"label":"toolonglabel"}`, `{"label":";$()"}`, `{"count":0}`, `{"count":6}`, `{"count":1.5}`, `{"mode":"facts","mode":"facts"}`, `null`, `[]`, `{} {}`, `{"label":null}`, strings.Repeat(" ", 4097)} {
		if _, err := e.Validate(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted invalid args %s", raw)
		}
	}
	if _, err := e.Validate(json.RawMessage(`{"mode":"facts","label":"probe","count":3}`)); err != nil {
		t.Fatal(err)
	}
	probe, _ := Lookup("fleet-probe-v1")
	if _, err := probe.Validate(json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
}

func TestBATSweepArgs(t *testing.T) {
	e, ok := Lookup("bat-sweep-report-v1")
	if !ok || e.DefaultTimeout != 600 || e.MaxTimeout != 600 || e.OutputCap != 64<<10 {
		t.Fatal("BAT constraints")
	}
	for _, raw := range []string{`{"hosts":["sample-host"]}`, `{"hosts":["sample-host"],"connector_tree_sha256":"bad"}`, `{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `","channels_file":"removed"}`, `{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `","include_excerpts":"true"}`, `{}`, `{"hosts":[]}`, `{"hosts":["bad.host"]}`, `{"hosts":[1]}`, `{"hosts":["a","b","c","d","e","f","g","h","i"]}`, `{"hosts":"sample"}`, `{"hosts":["sample"],"command":"true"}`} {
		if _, err := e.Validate(json.RawMessage(raw)); err == nil {
			t.Errorf("accepted %s", raw)
		}
	}
	if _, err := e.Validate(json.RawMessage(`{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `","include_excerpts":false}`)); err != nil {
		t.Fatal(err)
	}
}

func TestSpecDecodeExecutionModeAndLegacyCompatibility(t *testing.T) {
	for _, mode := range []string{"", "read", "write"} {
		spec := Spec{Kind: Kind, ScriptID: "fleet-probe-v1", Args: json.RawMessage(`{}`), ExecutionMode: mode}
		raw, err := json.Marshal(spec)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := Decode(raw)
		if err != nil || decoded.ExecutionMode != mode {
			t.Fatalf("mode %q: %v", mode, err)
		}
	}
}
