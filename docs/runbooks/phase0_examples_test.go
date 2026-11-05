package runbooks

import (
	"encoding/json"
	"testing"
)

func TestPhase0Schedules(t *testing.T) {
	if len(Phase0Schedules) == 0 {
		t.Fatal("Expected Phase0Schedules to be non-empty")
	}

	var schedules []interface{}
	err := json.Unmarshal(Phase0Schedules, &schedules)
	if err != nil {
		t.Fatalf("Expected Phase0Schedules to be valid JSON array, but got error: %v", err)
	}

	if len(schedules) == 0 {
		t.Error("Expected at least one schedule in Phase0Schedules")
	}
}
