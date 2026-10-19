package probe

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestUnitSemantics(t *testing.T) {
	for _, tc := range []struct {
		name, unit, class, active, typ, action string
		opt, ok                                bool
	}{
		{"oneshot idle", "backup.service", "static", "inactive", "oneshot", "", true, true},
		{"oneshot failed", "backup.service", "static", "failed", "oneshot", "", true, false},
		{"static service", "backup.service", "static", "inactive", "simple", "", true, true},
		{"indirect service", "backup.service", "indirect", "inactive", "simple", "", true, true},
		{"timer disabled", "job.timer", "disabled", "inactive", "", "enable --now", true, false},
		{"timer idle", "job.timer", "enabled", "inactive", "", "start", true, false},
		{"timer failed", "job.timer", "enabled", "failed", "", "start", true, false},
		{"service disabled", "job.service", "disabled", "inactive", "simple", "enable --now", true, false},
		{"service failed", "job.service", "enabled", "failed", "simple", "start", true, false},
		{"masked", "job.timer", "masked", "inactive", "", "", true, false},
		{"opt out", "job.timer", "disabled", "inactive", "", "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			p := UnitReadinessCollector{now: time.Now}
			p.runner = func(_ context.Context, _ time.Duration, cmd string, args ...string) (string, string, error) {
				if args[1] == "show" {
					return "LoadState=loaded\nUnitFileState=" + tc.class + "\nActiveState=" + tc.active + "\nType=" + tc.typ, "", nil
				}
				calls++
				want := []string{"--user", "start", "--", tc.unit}
				if tc.action == "enable --now" {
					want = []string{"--user", "enable", "--now", "--", tc.unit}
				}
				if cmd != "systemctl" || tc.action == "" || !reflect.DeepEqual(args, want) {
					t.Fatalf("unexpected command %s %v", cmd, args)
				}
				return "", "", nil
			}
			f := &model.ReadinessFacts{}
			// Model the effective default-on fleet profile, including oneshot cases.
			c := (model.FleetReadinessProfile{AutoRemediateUserUnits: true}).Effective(model.ReadinessConfig{ExpectedUserUnits: tc.unit})
			if !tc.opt {
				c.AutoRemediate = false
			}
			p.collect(t.Context(), c, f)
			if model.UnitOK(f.Units[tc.unit]) != tc.ok {
				t.Fatal(f.Units)
			}
			want := 0
			if tc.action != "" {
				want = 1
				if f.Units[tc.unit].Remediation.Action != tc.action {
					t.Fatal(f.Units)
				}
			}
			p.collect(t.Context(), c, f)
			if calls != want {
				t.Fatalf("commands %d want %d", calls, want)
			}
		})
	}
}

func TestDefaultOnEmptyExpectedUnitsDoesNothing(t *testing.T) {
	p := UnitReadinessCollector{now: time.Now, runner: func(context.Context, time.Duration, string, ...string) (string, string, error) {
		t.Fatal("empty expected units must not call systemctl")
		return "", "", nil
	}}
	c := (model.FleetReadinessProfile{AutoRemediateUserUnits: true}).Effective(model.ReadinessConfig{})
	p.collect(t.Context(), c, &model.ReadinessFacts{})
}
