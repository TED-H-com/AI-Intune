package probe

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/model"
	"runtime"
	"strings"
	"sync"
	"time"
)

type readinessRunner func(context.Context, time.Duration, string, ...string) (string, string, error)

// UnitReadinessCollector retains attempts in memory, including failed attempts.
// The user manager writes its own enable links even with ProtectHome=read-only.
type UnitReadinessCollector struct {
	mu       sync.Mutex
	attempts map[string]model.Remediation
	runner   readinessRunner
	now      func() time.Time
}

var readinessUnits = &UnitReadinessCollector{runner: run, now: time.Now}

func CollectReadinessUnits(ctx context.Context, c model.ReadinessConfig, f *model.ReadinessFacts) {
	if runtime.GOOS != "linux" || f == nil {
		return
	}
	readinessUnits.collect(ctx, c, f)
}
func (p *UnitReadinessCollector) collect(ctx context.Context, c model.ReadinessConfig, f *model.ReadinessFacts) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.attempts == nil {
		p.attempts = map[string]model.Remediation{}
	}
	f.Units = map[string]model.UnitFact{}
	names := strings.Split(c.ExpectedUserUnits, ",")
	seen := map[string]bool{}
	for _, name := range names {
		if !model.ValidUserUnit(name) || seen[name] || len(seen) >= 16 {
			continue
		}
		seen[name] = true
		u := p.probe(ctx, name)
		previous, attempted := p.attempts[name]
		if c.AutoRemediate && model.UnitRepairable(u) && (!attempted || p.now().Sub(previous.At) >= time.Hour) {
			action := "start"
			args := []string{"--user", "start", "--", name}
			if u.Disabled != nil && *u.Disabled {
				action = "enable --now"
				args = []string{"--user", "enable", "--now", "--", name}
			}
			r := model.Remediation{At: p.now().UTC(), Action: action}
			// Never include command output, error text, environment or file contents.
			_, _, err := p.runner(ctx, cmdTimeout, "systemctl", args...)
			u = p.probe(ctx, name)
			r.OK = err == nil && model.UnitOK(u)
			if !r.OK {
				r.Reason = "The user manager could not turn on the unit. Check its status on the machine."
			}
			p.attempts[name] = r
			previous = r
			attempted = true
		}
		if attempted {
			r := previous
			u.Remediation = &r
		}
		f.Units[name] = u
	}
}
func (p *UnitReadinessCollector) probe(ctx context.Context, name string) model.UnitFact {
	var u model.UnitFact
	out, _, err := p.runner(ctx, cmdTimeout, "systemctl", "--user", "show", name, "-p", "LoadState", "-p", "UnitFileState", "-p", "ActiveState", "-p", "Type")
	if err != nil && !strings.Contains(out, "LoadState=not-found") {
		return u
	}
	props := parseProps(out)
	boolean := func(v bool) *bool { return &v }
	if props["LoadState"] != "" {
		u.Loaded = boolean(props["LoadState"] == "loaded")
	}
	if props["UnitFileState"] != "" {
		u.Enabled = boolean(props["UnitFileState"] == "enabled" || props["UnitFileState"] == "enabled-runtime" || props["UnitFileState"] == "static" || props["UnitFileState"] == "indirect" || props["UnitFileState"] == "generated" || props["UnitFileState"] == "alias")
	}
	if props["ActiveState"] != "" {
		u.Active = boolean(props["ActiveState"] == "active")
	}
	u.Masked = boolean(props["LoadState"] == "masked" || strings.HasPrefix(props["UnitFileState"], "masked"))
	u.Disabled = boolean(props["UnitFileState"] == "disabled")
	if props["ActiveState"] != "" {
		u.Failed = boolean(props["ActiveState"] == "failed")
	}
	u.Oneshot = boolean(strings.HasSuffix(name, ".service") && (props["Type"] == "oneshot" || props["UnitFileState"] == "static" || props["UnitFileState"] == "indirect"))
	return u
}
