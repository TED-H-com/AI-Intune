package main

import (
	"github.com/teddashh/AI-Intune/internal/model"
	"testing"
)

func TestDiskTimerTransitionEchoIsScopeBound(t *testing.T) {
	c := model.Checkin{DiskTimers: []model.DiskTimerObservation{{Scope: "user"}, {Scope: "root"}}}
	echoDiskTimerTransitions(&c, map[string]model.DiskTimerTransition{"user": {Revision: 7, Nonce: "hub-user-challenge"}})
	if c.DiskTimers[0].TransitionRevision != 7 || c.DiskTimers[0].TransitionNonce != "hub-user-challenge" || c.DiskTimers[1].TransitionNonce != "" {
		t.Fatal(c.DiskTimers)
	}
	echoDiskTimerTransitions(&c, nil)
	if c.DiskTimers[0].TransitionNonce != "" {
		t.Fatal("challenge not cleared after Hub response")
	}
}
