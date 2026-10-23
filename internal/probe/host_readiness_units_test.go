package probe

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestUserUnitRepair(t *testing.T) {
	for _, tc := range []struct {
		name, state string

		opt, fail bool
		want      int
	}{
		{"off opt out", "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive", false, false, 0},
		{"off opt in", "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive", true, false, 1},
		{"failed repair", "LoadState=loaded\nUnitFileState=disabled\nActiveState=inactive", true, true, 1},
		{"masked", "LoadState=loaded\nUnitFileState=masked\nActiveState=inactive", true, false, 0},
		{"missing", "LoadState=not-found", true, false, 0},
		{"unknown", "", true, false, 0},
		{"already on", "LoadState=loaded\nUnitFileState=enabled\nActiveState=active", true, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			calls := 0
			state := tc.state
			p := UnitReadinessCollector{now: func() time.Time { return now }}
			p.runner = func(_ context.Context, timeout time.Duration, command string, args ...string) (string, string, error) {
				if command != "systemctl" || timeout != cmdTimeout {
					t.Fatal(command, timeout)
				}
				if len(args) > 1 && args[1] == "enable" {
					if !reflect.DeepEqual(args, []string{"--user", "enable", "--now", "--", "worker.timer"}) {
						t.Fatal(args)
					}
					calls++
					if tc.fail {
						return "secret output", "secret stderr", errors.New("secret")
					}
					state = "LoadState=loaded\nUnitFileState=enabled\nActiveState=active"
					return "", "", nil
				}
				if !reflect.DeepEqual(args, []string{"--user", "show", "worker.timer", "-p", "LoadState", "-p", "UnitFileState", "-p", "ActiveState", "-p", "Type"}) {
					t.Fatal(args)
				}
				if state == "LoadState=not-found" {
					return state, "", errors.New("not found")
				}
				return state, "", nil
			}
			c := model.ReadinessConfig{ExpectedUserUnits: "worker.timer,../bad.service,worker.timer", AutoRemediate: tc.opt}
			f := &model.ReadinessFacts{}
			p.collect(t.Context(), c, f)
			if calls != tc.want || len(f.Units) != 1 {
				t.Fatal(calls, f)
			}
			if tc.state == "LoadState=not-found" && (f.Units["worker.timer"].Loaded == nil || *f.Units["worker.timer"].Loaded) {
				t.Fatal("missing unit not reported")
			}
			if tc.want == 1 {
				r := f.Units["worker.timer"].Remediation
				if r == nil || r.OK == tc.fail || strings.Contains(r.Reason, "secret") {
					t.Fatal(r)
				}
				// Force the unit off again: no second attempt before one hour.
				state = tc.state
				p.collect(t.Context(), c, f)
				if calls != 1 {
					t.Fatal("rate limit bypassed")
				}
				now = now.Add(time.Hour)
				p.collect(t.Context(), c, f)
				if calls != 2 {
					t.Fatal("retry not allowed after hour")
				}
				c.AutoRemediate = false
				now = now.Add(time.Hour)
				state = tc.state
				p.collect(t.Context(), c, f)
				if calls != 2 {
					t.Fatal("opt out ignored")
				}
			}
		})
	}
}
