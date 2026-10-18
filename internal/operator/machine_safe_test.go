package operator

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestMachineSafeStoredDetailAndEvidence(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	id, _, err := st.CreateEnrollTokenFor("password=fixture-value", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	s := New(st)
	safe, err := s.MachineSafe(id, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(safe)
	if strings.Contains(string(raw), "fixture-value") || !safe.Redacted || safe.Redactions < 2 || len(safe.RedactionFlags) == 0 {
		t.Fatal("stored display name leaked")
	}
	human, err := s.MachineDetail(id, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(human)
	if !strings.Contains(string(raw), "fixture-value") {
		t.Fatal("human detail changed")
	}
	if _, err = s.MachineSafe("missing", time.Now()); err == nil {
		t.Fatal("missing machine accepted")
	}
}
func TestSafeProjectionRecursesEveryString(t *testing.T) {
	result, err := scrubMachineProjection(map[string]any{"nested": []any{map[string]any{"text": "secret=fixture-value"}, "password=other-value", 42}})
	if err != nil || result.Redactions != 2 || len(result.RedactionFlags) != 1 || result.RedactionFlags[0] != "credential_assignment" {
		t.Fatal("recursive projection failed")
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "fixture-value") || strings.Contains(string(raw), "other-value") {
		t.Fatal("nested text leaked")
	}
}
