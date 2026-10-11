package main

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/diskpolicy"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"os"
	"runtime"
	"time"
)

type scriptExecutor struct{}

func (scriptExecutor) Run(ctx context.Context, job model.JobResponse) ([]model.JobVerificationRequest, error) {
	reject := func() ([]model.JobVerificationRequest, error) {
		return nil, &rejectError{Code: deploy.PreconditionFailed, Detail: "script catalog identity, hash, args, OS or timeout mismatch"}
	}
	spec, err := scriptcatalog.Decode(job.Spec)
	if err != nil {
		return reject()
	}
	e, ok := scriptcatalog.Lookup(spec.ScriptID)
	if !ok || spec.ScriptSHA256 != e.SHA256 || scriptcatalog.Digest(e.Bytes) != spec.ScriptSHA256 || !e.AllowsOS(runtime.GOOS) || job.ResourceKind != scriptcatalog.Kind || job.ResourceID != e.ID || job.ExecutionTimeout < 1 || job.ExecutionTimeout > e.MaxTimeout || job.Irreversible {
		return reject()
	}
	if os.Geteuid() == 0 {
		return nil, &rejectError{Code: deploy.PreconditionFailed, Detail: "script_v1 refuses root execution in phase 1"}
	}
	if scriptcatalog.IsDiskSafe(e.ID) && spec.ExecutionMode != e.Mode {
		return reject()
	}
	if scriptcatalog.IsDiskSafe(e.ID) {
		_, canonical, digest, policyErr := diskpolicy.CanonicalDiskPolicy(spec.Policy)
		var args struct {
			Digest string `json:"policy_digest"`
		}
		_ = json.Unmarshal(spec.Args, &args)
		if policyErr != nil || args.Digest != digest || string(canonical) != string(spec.Policy) {
			return reject()
		}
	}
	args, err := e.Validate(spec.Args)
	if err != nil {
		return reject()
	}
	result, err := scriptcatalog.RunPolicy(ctx, e, args, job.ExecutionTimeout, spec.Policy)
	if err != nil {
		return nil, err
	}
	metadata := result
	metadata.Stdout = ""
	metadata.Stderr = ""
	raw, _ := json.Marshal(metadata)
	return []model.JobVerificationRequest{{RuleID: scriptcatalog.Kind, Command: e.ID, ExitCode: result.ExitCode, StdoutExcerpt: result.Stdout, StderrExcerpt: result.Stderr, Passed: result.ExitCode == 0 && !result.TimedOut, VerifiedAt: time.Now().UTC()}, {RuleID: "script_v1_metadata", Command: string(raw), ExitCode: result.ExitCode, Passed: result.ExitCode == 0 && !result.TimedOut, VerifiedAt: time.Now().UTC()}}, nil
}
