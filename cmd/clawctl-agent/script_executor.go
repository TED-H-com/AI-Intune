package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/diskpolicy"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"net/url"
	"os"
	"runtime"
	"strings"
	"time"
)

type scriptExecutor struct{ hubURL, token string }
type boundedReportBuffer struct{ bytes.Buffer }

func (b *boundedReportBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > diskreport.MaxBytes {
		return 0, fmt.Errorf("report limit exceeded")
	}
	return b.Buffer.Write(p)
}

func (executor scriptExecutor) Run(ctx context.Context, job model.JobResponse) ([]model.JobVerificationRequest, error) {
	reject := func() ([]model.JobVerificationRequest, error) {
		return nil, &rejectError{Code: deploy.PreconditionFailed, Detail: "script catalog identity, hash, args, OS or timeout mismatch"}
	}
	spec, err := scriptcatalog.Decode(job.Spec)
	if err != nil {
		return reject()
	}
	e, ok := scriptcatalog.Lookup(spec.ScriptID)
	if !ok || spec.ScriptSHA256 != e.SHA256 || scriptcatalog.Digest(e.Bytes) != spec.ScriptSHA256 || !e.AllowsOS(runtime.GOOS) || job.ResourceKind != scriptcatalog.Kind || job.ResourceID != e.ID || job.ExecutionTimeout < 1 || job.ExecutionTimeout > e.MaxTimeout || (job.Irreversible && !scriptcatalog.IsDiskAction(e.ID)) {
		return reject()
	}
	if os.Geteuid() == 0 {
		return nil, &rejectError{Code: deploy.PreconditionFailed, Detail: "script_v1 refuses root execution in phase 1"}
	}
	if scriptcatalog.IsDisk(e.ID) && spec.ExecutionMode != e.Mode {
		return reject()
	}
	if scriptcatalog.IsDisk(e.ID) {
		_, canonical, digest, policyErr := diskpolicy.CanonicalDiskPolicy(spec.Policy)
		var args struct {
			Digest string `json:"policy_digest"`
		}
		_ = json.Unmarshal(spec.Args, &args)
		if policyErr != nil || (!scriptcatalog.IsDiskAction(e.ID) && args.Digest != digest) || string(canonical) != string(spec.Policy) {
			return reject()
		}
	}
	args, err := e.Validate(spec.Args)
	if err != nil {
		return reject()
	}
	var result scriptcatalog.Result
	if scriptcatalog.IsDiskAction(e.ID) {
		if executor.hubURL == "" || executor.token == "" || job.Irreversible != (e.ID == "disk-approved-delete-v1" || e.ID == "disk-quarantine-expire-v1") {
			return reject()
		}
		var binding struct {
			ID     string `json:"manifest_id"`
			Digest string `json:"manifest_digest"`
		}
		if e.ID == "disk-quarantine-expire-v1" {
			var expiry struct {
				Digest string `json:"policy_digest"`
			}
			_ = json.Unmarshal(args, &expiry)
			binding.ID = "expiry"
			binding.Digest = expiry.Digest
		}
		if json.Unmarshal(args, &binding) != nil || binding.ID == "" {
			return reject()
		}
		renew := func(callCtx context.Context) (json.RawMessage, error) {
			return executor.fetchDiskGrant(callCtx, job.JobID, binding.ID, binding.Digest)
		}
		grant, grantErr := renew(ctx)
		if grantErr != nil {
			return nil, &rejectError{Code: deploy.PreconditionFailed, Detail: "signed disk action grant unavailable"}
		}
		var private boundedReportBuffer
		result, err = scriptcatalog.RunDiskAction(ctx, e, args, job.ExecutionTimeout, scriptcatalog.DiskActionRun{MachineID: job.MachineID, JobID: job.JobID, Authorization: grant, Renew: renew, Sink: &private})
		if err == nil && result.ExitCode == 0 && !result.TimedOut {
			var receipt struct {
				Digest string `json:"digest"`
			}
			endpoint := strings.TrimRight(executor.hubURL, "/") + "/v1/disk-actions/" + url.PathEscape(job.JobID) + "/results"
			err = postJSONStrict(ctx, endpoint, executor.token, json.RawMessage(private.Bytes()), &receipt)
		}
	} else if e.ID == "disk-deep-report-v1" {
		if executor.hubURL == "" || executor.token == "" {
			return reject()
		}
		var private boundedReportBuffer
		result, err = scriptcatalog.RunReport(ctx, e, args, job.ExecutionTimeout, spec.Policy, &private)
		if err == nil && result.ExitCode == 0 && !result.TimedOut {
			var canonical []byte
			var report diskreport.Report
			report, canonical, err = diskreport.Decode(private.Bytes())
			endpoint := strings.TrimRight(executor.hubURL, "/") + "/v1/disk-reports/" + url.PathEscape(job.JobID)
			var receipt diskreport.Receipt
			if err == nil {
				for offset, sequence := 0, 0; offset < len(canonical); sequence++ {
					end := offset + diskreport.MaxChunk
					if end > len(canonical) {
						end = len(canonical)
					}
					data := canonical[offset:end]
					err = postJSONStrict(ctx, endpoint+"/chunks", executor.token, diskreport.Chunk{Sequence: sequence, Digest: diskreport.Digest(data), Data: data}, &receipt)
					if err != nil {
						break
					}
					offset = end
				}
			}
			if err == nil {
				err = postJSONStrict(ctx, endpoint+"/complete", executor.token, diskreport.Complete{Digest: diskreport.Digest(canonical), ItemCount: len(report.Items)}, &receipt)
			}
			if err == nil {
				safe, _ := json.Marshal(receipt)
				result.Stdout = string(safe)
				result.StdoutTruncated = false
				result.StdoutSHA256 = scriptcatalog.Digest(safe)
			}
		}
	} else {
		result, err = scriptcatalog.RunPolicy(ctx, e, args, job.ExecutionTimeout, spec.Policy)
	}
	if err != nil {
		return nil, err
	}
	metadata := result
	metadata.Stdout = ""
	metadata.Stderr = ""
	raw, _ := json.Marshal(metadata)
	return []model.JobVerificationRequest{{RuleID: scriptcatalog.Kind, Command: e.ID, ExitCode: result.ExitCode, StdoutExcerpt: result.Stdout, StderrExcerpt: result.Stderr, Passed: result.ExitCode == 0 && !result.TimedOut, VerifiedAt: time.Now().UTC()}, {RuleID: "script_v1_metadata", Command: string(raw), ExitCode: result.ExitCode, Passed: result.ExitCode == 0 && !result.TimedOut, VerifiedAt: time.Now().UTC()}}, nil
}
