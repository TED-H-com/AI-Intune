package main

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"strings"
	"testing"
)

func TestHeartbeatActivityDoesNotInventProgress(t *testing.T) {
	process := strings.Repeat("a", 64)
	first := heartbeatActivity(process, 1, 0)
	next := heartbeatActivity(process, 100, 0)
	if first.CallSignature != next.CallSignature || next.Progress != 0 || next.TotalCalls != 100 {
		t.Fatal("heartbeat invented progress")
	}
	if err := store.ValidateLoopActivity([]model.CallActivity{next}); err != nil {
		t.Fatal(err)
	}
	if heartbeatActivity(process, 101, 1).Progress != 1 {
		t.Fatal("observation progress lost")
	}
}
