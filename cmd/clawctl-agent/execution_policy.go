package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/teddashh/AI-Intune/internal/model"
	"io"
	"os"
	"path/filepath"
	"sync"
)

var errExecutionBlocked = errors.New("machine execution is blocked by policy")

// All production execution starts blocked until a fresh check-in supplies a
// valid non-regressing policy. Last accepted policy is persisted before use.
type executionGuard struct {
	mu         sync.Mutex
	policy     model.ExecutionPolicy
	authorized bool
	changed    chan struct{}
	scopes     map[*context.CancelFunc]context.CancelFunc
}

func newExecutionGuard(p *model.ExecutionPolicy) *executionGuard {
	value := model.ExecutionPolicy{Mode: model.ExecutionManaged, Revision: 1}
	if p != nil {
		value = *p
	}
	return &executionGuard{policy: value, changed: make(chan struct{}), scopes: map[*context.CancelFunc]context.CancelFunc{}}
}
func (g *executionGuard) allowedLocked() bool {
	return g.authorized && g.policy.Validate() == nil && g.policy.Mode == model.ExecutionManaged
}
func (g *executionGuard) Allowed() bool {
	if g == nil {
		return true
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.allowedLocked()
}
func (g *executionGuard) Snapshot() model.ExecutionPolicy {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.policy
}
func (g *executionGuard) Changed() <-chan struct{} {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.changed
}
func (g *executionGuard) notifyLocked() { close(g.changed); g.changed = make(chan struct{}) }
func (g *executionGuard) blockLocked() {
	g.authorized = false
	for _, cancel := range g.scopes {
		cancel()
	}
	g.notifyLocked()
}
func (g *executionGuard) Adopt(p *model.ExecutionPolicy, persist func(model.ExecutionPolicy) error) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p == nil || p.Mode == model.ExecutionMonitorOnly && !monitorOnlyRootSafe() || p.Validate() != nil || p.Revision < g.policy.Revision || p.Revision == g.policy.Revision && p.Mode != g.policy.Mode {
		g.blockLocked()
		return errExecutionBlocked
	}
	wasAllowed := g.allowedLocked()
	if *p != g.policy || !g.authorized {
		if err := persist(*p); err != nil {
			g.blockLocked()
			return err
		}
	}
	g.policy = *p
	g.authorized = true
	if !g.allowedLocked() {
		for _, cancel := range g.scopes {
			cancel()
		}
	}
	if wasAllowed != g.allowedLocked() {
		g.notifyLocked()
	}
	return nil
}
func (g *executionGuard) Scope(parent context.Context) (context.Context, context.CancelFunc, error) {
	if g == nil {
		ctx, cancel := context.WithCancel(parent)
		return ctx, cancel, nil
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.allowedLocked() {
		return nil, nil, errExecutionBlocked
	}
	ctx, cancel := context.WithCancel(parent)
	key := &cancel
	g.scopes[key] = cancel
	return ctx, func() { cancel(); g.mu.Lock(); delete(g.scopes, key); g.mu.Unlock() }, nil
}
func (c config) executionAllowed() bool {
	if c.execution != nil {
		return c.execution.Allowed()
	}
	return c.ExecutionPolicy == nil || c.ExecutionPolicy.Validate() == nil && c.ExecutionPolicy.Mode == model.ExecutionManaged
}
func adoptExecutionPolicy(cfg config, p *model.ExecutionPolicy) error {
	return cfg.execution.Adopt(p, func(next model.ExecutionPolicy) error {
		copy := cfg
		copy.ExecutionPolicy = &next
		copy.execution = nil
		return saveConfig(copy)
	})
}
func startExecutionLoops(ctx context.Context, cfg config, nudge chan<- struct{}) {
	for ctx.Err() == nil {
		changed := cfg.execution.Changed()
		executionCtx, cancel, err := cfg.execution.Scope(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-changed:
				continue
			}
		}
		startJobs(executionCtx, cfg, nudge)
		startSignins(executionCtx, cfg)
		go runTerminalLink(executionCtx, cfg)
		<-executionCtx.Done()
		cancel()
	}
}

type policyExecutor struct {
	inner executor
	guard *executionGuard
}

func (e policyExecutor) Run(ctx context.Context, job model.JobResponse) ([]model.JobVerificationRequest, error) {
	scope, cancel, err := e.guard.Scope(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	return e.inner.Run(scope, job)
}
func (e policyExecutor) AfterSucceeded(ctx context.Context, job model.JobResponse) []string {
	scope, cancel, err := e.guard.Scope(ctx)
	if err != nil {
		return nil
	}
	defer cancel()
	if r, ok := e.inner.(retainer); ok {
		return r.AfterSucceeded(scope, job)
	}
	return nil
}

// An older root applier cannot enforce this policy. Such a host must update or
// remove that applier before it can enroll or switch to monitor only.
func monitorOnlyRootSafe() bool {
	return monitorOnlyRootSafeAt("/usr/local/sbin/clawctl-fleet-apply", configPath())
}
func monitorOnlyRootSafeAt(applier, agentConfig string) bool {
	file, err := os.Open(applier)
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	if err != nil {
		return false
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, 128<<10))
	if err != nil || !bytes.Contains(raw, []byte("def execution_allowed(self, home=None, uid=None):")) {
		return false
	}
	home, err := os.UserHomeDir()
	if err != nil || filepath.Clean(agentConfig) != filepath.Join(home, ".config/clawctl/agent.json") {
		return false
	}
	return true
}
