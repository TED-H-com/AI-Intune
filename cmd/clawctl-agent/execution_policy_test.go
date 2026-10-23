package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestExecutionPolicyStartsBlockedPersistsAndCancels(t *testing.T) {
	guard := newExecutionGuard(nil)
	if guard.Allowed() {
		t.Fatal("execution before policy handshake")
	}
	persisted := model.ExecutionPolicy{}
	save := func(p model.ExecutionPolicy) error { persisted = p; return nil }
	managed := model.ExecutionPolicy{Mode: model.ExecutionManaged, Revision: 1}
	if err := guard.Adopt(&managed, save); err != nil || !guard.Allowed() || persisted != managed {
		t.Fatal("managed policy not adopted", err)
	}
	ctx, cancel, err := guard.Scope(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	monitor := model.ExecutionPolicy{Mode: model.ExecutionMonitorOnly, Revision: 2}
	if err := guard.Adopt(&monitor, save); err != nil {
		t.Fatal(err)
	}
	if guard.Allowed() || ctx.Err() == nil {
		t.Fatal("monitor profile did not stop execution")
	}
	calls := 0
	executor := policyExecutor{guard: guard, inner: executorFunc(func(context.Context, model.JobResponse) ([]model.JobVerificationRequest, error) {
		calls++
		return nil, nil
	})}
	if _, err := executor.Run(context.Background(), model.JobResponse{}); err == nil || calls != 0 {
		t.Fatal("executor ran in monitor mode")
	}
	for _, p := range []*model.ExecutionPolicy{nil, &managed, {Mode: "unknown", Revision: 3}, {Mode: model.ExecutionManaged, Revision: 2}} {
		if err := guard.Adopt(p, save); err == nil || guard.Allowed() {
			t.Fatal("invalid or regressing policy enabled execution")
		}
	}
	managed.Revision = 3
	if err := guard.Adopt(&managed, func(model.ExecutionPolicy) error { return errors.New("disk full") }); err == nil || guard.Allowed() {
		t.Fatal("execution enabled before persistence")
	}
	if err := guard.Adopt(&managed, save); err != nil || !guard.Allowed() {
		t.Fatal("valid revision refused", err)
	}
}
func TestExecutionPolicyMonitorBlocksEveryLocalEntry(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	guard := newExecutionGuard(&model.ExecutionPolicy{Mode: model.ExecutionMonitorOnly, Revision: 1})
	cfg := config{ExecutionPolicy: &model.ExecutionPolicy{Mode: model.ExecutionMonitorOnly, Revision: 1}, execution: guard, JobsEnabled: true}
	if cfg.executionAllowed() {
		t.Fatal("monitor execution allowed")
	}
	// These entrypoints must return before creating worker state or connecting.
	startJobs(context.Background(), cfg, make(chan struct{}, 1))
	startSignins(context.Background(), cfg)
	runTerminalLinkAttempt(context.Background(), cfg, terminalLinkDeps{userHomeDir: func() (string, error) { t.Fatal("terminal dependency called"); return "", nil }})
	agentSigninPolicy.Store(guard)
	t.Cleanup(func() { agentSigninPolicy.Store(nil) })
	handleSigninCommand(context.Background(), model.SigninCommand{})
	yes := true
	profile := model.HostProfile{LidIgnore: &yes}
	digest, _ := profile.Digest()
	resp := model.CheckinResponse{ExecutionPolicy: cfg.ExecutionPolicy, HostProfile: &profile, HostProfileDigest: digest, DiskJobs: []model.DiskJob{{ID: "blocked-disk"}}}
	if adoptHostProfile(resp) == nil {
		t.Fatal("root handoff accepted")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".config/clawctl/host-profile.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("host handoff written")
	}
	if _, err := os.Stat(filepath.Join(os.Getenv("HOME"), ".config/clawctl/disk-jobs.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("disk handoff written")
	}
}

func TestMonitorOnlyRequiresGuardedRootApplier(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	applier := filepath.Join(home, "applier")
	config := filepath.Join(home, ".config/clawctl/agent.json")
	if !monitorOnlyRootSafeAt(applier, config) {
		t.Fatal("no applier refused")
	}
	if err := os.WriteFile(applier, []byte("old root applier"), 0600); err != nil {
		t.Fatal(err)
	}
	if monitorOnlyRootSafeAt(applier, config) {
		t.Fatal("unguarded applier accepted")
	}
	if err := os.WriteFile(applier, []byte("def execution_allowed(self, home=None, uid=None):"), 0600); err != nil {
		t.Fatal(err)
	}
	if !monitorOnlyRootSafeAt(applier, config) {
		t.Fatal("guarded applier refused")
	}
	if monitorOnlyRootSafeAt(applier, filepath.Join(home, "custom-agent.json")) {
		t.Fatal("custom config bypassed fixed root policy")
	}
}
