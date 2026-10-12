package store

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/maintenance"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

func TestDiskMountPolicyRejectsRotatingLabels(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	policy := DefaultDiskPolicy()
	policy.DataMounts = []string{"/data"}
	rev := int64(0)
	pReq := DiskPolicyRequest{ID: "mount-policy", Body: mustScriptJSON(policy), ExpectedRevision: &rev, Reason: "declare data mount"}
	p, err := s.DiskPolicyUpsert(pReq, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	pReq.PreviewDigest = p.PreviewDigest
	pReq.ExpiresAt = p.ExpiresAt
	applied, err := s.DiskPolicyUpsert(pReq, true, "mount-policy", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.Args = mustScriptJSON(map[string]string{"scope": "user", "policy_id": applied.Policy.ID, "policy_digest": applied.Policy.Digest})
	preview, err := s.ScriptRun(req, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	run, err := s.ScriptRun(req, true, "mount-report", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	for iteration := 0; iteration < 2; iteration++ {
		env := DiskSafeEnvelope{}
		env.Summary.Categories = map[string]maintenance.SummaryCategory{}
		env.Operation.Schema = "disk-safe/v2"
		env.Operation.PolicyID = applied.Policy.ID
		env.Operation.PolicyDigest = applied.Policy.Digest
		env.Summary.Schema = "fleet-disk-clean/v1"
		env.Summary.Version = "2.0.0"
		env.Summary.Scope = "user"
		env.Summary.Mode = "apply"
		env.Summary.Host = "agent"
		env.Summary.User = "agent"
		env.Summary.TS = fmtTime(now)
		env.Summary.ConfigDigest = applied.Policy.Digest
		env.Summary.Disk.Mount = "/"
		env.Operation.Mounts = []DiskMountUsage{{Mount: "/data", TotalBytes: 100, AvailableBytes: 1, Percent: 99}}
		for i := 0; i < 40; i++ {
			env.Operation.Mounts = append(env.Operation.Mounts, DiskMountUsage{Mount: fmt.Sprintf("/fabricated-%d-%d", iteration, i), TotalBytes: 100, AvailableBytes: 1, Percent: 99})
		}
		raw, _ := json.Marshal(env)
		if _, err = s.db.Exec(`INSERT INTO verification_results(verification_id,job_id,machine_id,rule_id,command,exit_code,passed,verified_at,received_at,producer_id,stdout_excerpt) VALUES(?,?,?,'script_v1','test',0,1,?,?,?,?)`, fmt.Sprintf("mount-report-%d", iteration), run.JobIDs[0], req.Targets[0], fmtTime(now), fmtTime(now.Add(time.Duration(iteration)*time.Second)), req.Targets[0], string(raw)); err != nil {
			t.Fatal(err)
		}
		status, err := s.DiskOpsStatus(req.Targets[0])
		if err != nil {
			t.Fatal(err)
		}
		if status.IgnoredMounts != 32 {
			t.Fatalf("ignored metric not saturated: %d", status.IgnoredMounts)
		}
		for _, m := range status.Mounts {
			if m.Mount != "/" && m.Mount != "/data" {
				t.Fatalf("undeclared mount admitted: %+v", m)
			}
		}
		if err = s.ReconcileDiskAlerts(now.Add(time.Duration(iteration) * time.Second)); err != nil {
			t.Fatal(err)
		}
		alerts, err := s.DiskAlertsList(req.Targets[0])
		if err != nil {
			t.Fatal(err)
		}
		if len(alerts) != 2 {
			t.Fatalf("declared mount alerts missing: %+v", alerts)
		}
		for _, a := range alerts {
			if len(a.ConditionKey) > 6 && a.ConditionKey[:6] == "mount:" && a.ConditionKey != "mount:"+scriptcatalog.Digest([]byte("/data"))+":warn" && a.ConditionKey != "mount:"+scriptcatalog.Digest([]byte("/data"))+":critical" {
				t.Fatalf("fabricated alert: %+v", a)
			}
		}
	}
	// Removing a declaration from the current policy rejects even a previously valid report.
	policy.DataMounts = nil
	rev = 1
	pReq = DiskPolicyRequest{ID: "mount-policy", Body: mustScriptJSON(policy), ExpectedRevision: &rev, Reason: "remove data mount"}
	p, err = s.DiskPolicyUpsert(pReq, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	pReq.PreviewDigest, pReq.ExpiresAt = p.PreviewDigest, p.ExpiresAt
	if _, err = s.DiskPolicyUpsert(pReq, true, "remove-mount", diskAdmin()); err != nil {
		t.Fatal(err)
	}
	status, err := s.DiskOpsStatus(req.Targets[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range status.Mounts {
		if m.Mount != "/" {
			t.Fatalf("old policy declaration accepted: %+v", m)
		}
	}

}

func TestDiskMountCapMissingExpiryAndRetention(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	value := 99
	for i := 0; i < 20; i++ {
		if err := s.DiskAlertReading(machine, fmt.Sprintf("mount:legacy-%d:critical", i), "critical", &value, 93, now); err != nil {
			t.Fatal(err)
		}
	}
	alerts, err := s.DiskAlertsList(machine)
	if err != nil || len(alerts) != 8 {
		t.Fatalf("cap: %d %v", len(alerts), err)
	}
	for _, a := range alerts {
		if err = s.DiskAlertReading(machine, a.ConditionKey, "critical", nil, 93, now.Add(23*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.ExpireMissingDiskMounts(now.Add(24*time.Hour - time.Second)); err != nil {
		t.Fatal(err)
	}
	alerts, _ = s.DiskAlertsList(machine)
	for _, a := range alerts {
		if a.ClearedAt != nil {
			t.Fatal("unknown mount cleared before expiry")
		}
	}
	// A fresh declared result restarts the missing interval.
	key := alerts[0].ConditionKey
	if err = s.DiskAlertReading(machine, key, "critical", &value, 93, now.Add(23*time.Hour)); err != nil {
		t.Fatal(err)
	}
	// Unknown and fresh timestamps must differ: an earlier unknown reading at the same timestamp is not fresh evidence.
	if err = s.DiskAlertReading(machine, key, "critical", &value, 93, now.Add(23*time.Hour+time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = s.ExpireMissingDiskMounts(now.Add(24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	alerts, _ = s.DiskAlertsList(machine)
	open := 0
	for _, a := range alerts {
		if a.ClearedAt == nil {
			open++
			if a.ConditionKey != key {
				t.Fatal("unexpected surviving mount")
			}
		} else if a.ClearedReason != "mount_missing" {
			t.Fatalf("expiry reported recovery: %+v", a)
		}
	}
	if open != 1 {
		t.Fatalf("fresh mount expired: open=%d", open)
	}
	if err = s.ExpireMissingDiskMounts(now.Add(48 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err = s.PruneDiskAlerts(now.Add(140 * 24 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	alerts, _ = s.DiskAlertsList(machine)
	if len(alerts) != 0 {
		t.Fatalf("missing episodes not retained/pruned: %d", len(alerts))
	}
}
