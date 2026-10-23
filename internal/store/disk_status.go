package store

import (
	"database/sql"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/maintenance"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"math/big"
	"time"
)

type DiskMountUsage struct {
	Growth         *DiskGrowth `json:"growth,omitempty"`
	Mount          string      `json:"mount"`
	TotalBytes     int64       `json:"total_bytes"`
	AvailableBytes int64       `json:"available_bytes"`
	Percent        int         `json:"percent"`
	MeasuredAt     string      `json:"measured_at,omitempty"`
}
type DiskSafeEnvelope struct {
	ReceivedAt time.Time           `json:"-"`
	Summary    maintenance.Summary `json:"summary"`
	Operation  struct {
		SkipCode     string           `json:"skip_code"`
		Schema       string           `json:"schema"`
		PolicyID     string           `json:"policy_id"`
		PolicyDigest string           `json:"policy_digest"`
		Ownership    string           `json:"ownership"`
		Protections  []string         `json:"protections"`
		Mounts       []DiskMountUsage `json:"mounts"`
	} `json:"operation"`
}
type DiskOpsStatus struct {
	Growth           []DiskGrowth          `json:"growth"`
	IgnoredMounts    int                   `json:"ignored_mounts"`
	MachineID        string                `json:"machine_id"`
	Mounts           []DiskMountUsage      `json:"mounts"`
	Thresholds       DiskThresholds        `json:"thresholds"`
	LastSafeTier     *DiskSafeEnvelope     `json:"last_safe_tier"`
	Preview          *DiskSafeEnvelope     `json:"preview"`
	Skips            map[string]string     `json:"skips"`
	Ownership        map[string]string     `json:"ownership"`
	Canary           map[string]DiskCanary `json:"canary"`
	Supervision      DiskSupervision       `json:"supervision"`
	Alerts           []DiskAlert           `json:"alerts"`
	OwnershipRecords []DiskOwnership       `json:"ownership_records"`
	WritesEnabled    bool                  `json:"writes_enabled"`
	Actions          DiskActionMetrics     `json:"actions"`
}

func (s *Store) DiskOpsStatus(id string) (DiskOpsStatus, error) {
	out := DiskOpsStatus{MachineID: id, Mounts: []DiskMountUsage{}, Thresholds: DefaultDiskPolicy().Thresholds, Skips: map[string]string{}, Ownership: map[string]string{"user": "local-owned", "root": "local-owned"}, WritesEnabled: s.DiskOpsWritesEnabled()}
	var exists int
	if err := s.rdb.QueryRow(`SELECT COUNT(*) FROM machine_registry WHERE machine_id=?`, id).Scan(&exists); err != nil {
		return out, err
	}
	if exists != 1 {
		return out, operatorError(OperatorCodeMachineNotFound, "machine not found")
	}
	var total, avail int64
	var measured string
	err := s.rdb.QueryRow(`SELECT disk_total_bytes,disk_free_bytes,sent_at FROM machine_checkins WHERE machine_id=? ORDER BY received_at DESC,rowid DESC LIMIT 1`, id).Scan(&total, &avail, &measured)
	if err != nil && err != sql.ErrNoRows {
		return out, err
	}
	if total > 0 && avail >= 0 && avail <= total {
		out.Mounts = append(out.Mounts, DiskMountUsage{Mount: "/", TotalBytes: total, AvailableBytes: avail, Percent: diskUsagePercent(total, avail), MeasuredAt: measured})
	}
	for _, script := range []string{"disk-safe-clean-v2", "disk-safe-preview-v2"} {
		var raw, spec, received string
		err = s.rdb.QueryRow(`SELECT v.stdout_excerpt,d.spec,v.received_at FROM verification_results v JOIN jobs j ON j.job_id=v.job_id JOIN desired_state d ON d.desired_id=j.desired_id WHERE j.machine_id=? AND d.resource_kind='script_v1' AND d.resource_id=? AND v.rule_id='script_v1' AND v.exit_code=0 AND v.passed=1 AND v.evidence_role=? AND v.producer_kind=? AND v.producer_id=? AND v.authority=? ORDER BY v.received_at DESC,v.rowid DESC LIMIT 1`, id, script, JobVerificationRoleExecutor, JobVerificationProducerExecutorAgent, id, JobVerificationAuthorityMachineLease).Scan(&raw, &spec, &received)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return out, err
		}
		var envelope DiskSafeEnvelope
		if len(raw) > 64<<10 || json.Unmarshal([]byte(raw), &envelope) != nil {
			continue
		}
		envelope.ReceivedAt, err = time.Parse(time.RFC3339Nano, received)
		if err != nil {
			return out, err
		}
		summary, _ := json.Marshal(envelope.Summary)
		if _, e := maintenance.ParseSummary(summary); e != nil {
			continue
		}
		pinned, e := scriptcatalog.Decode([]byte(spec))
		if e != nil {
			continue
		}
		policy, _, digest, e := CanonicalDiskPolicy(pinned.Policy)
		if e != nil || digest != envelope.Operation.PolicyDigest {
			continue
		}
		if envelope.Operation.Schema != "disk-safe/v2" || envelope.Summary.ConfigDigest != digest {
			continue
		}
		var args struct {
			ID     string `json:"policy_id"`
			Digest string `json:"policy_digest"`
		}
		_ = json.Unmarshal(pinned.Args, &args)
		if envelope.Operation.PolicyID != args.ID || args.Digest != digest {
			continue
		}
		if current, err := s.DiskPolicy(args.ID); err == nil {
			if active, _, _, e := CanonicalDiskPolicy(current.Body); e == nil {
				policy = active
			}
		}
		allowed := map[string]bool{"/": true}
		// Only the current human-owned policy can authorize mount identities.
		policyID := args.ID
		// A current machine schedule takes precedence over a report from an older policy ID.
		var scheduledID string
		e = s.rdb.QueryRow(`SELECT json_extract(args,'$.policy_id') FROM schedules WHERE script_id IN ('disk-safe-preview-v2','disk-safe-clean-v2') AND json_extract(args,'$.scope')=? AND EXISTS(SELECT 1 FROM json_each(targets) WHERE value=?) ORDER BY CASE WHEN script_id='disk-safe-clean-v2' THEN 0 ELSE 1 END,id LIMIT 1`, envelope.Summary.Scope, id).Scan(&scheduledID)
		if e != nil && e != sql.ErrNoRows {
			return out, e
		}
		if e == nil {
			policyID = scheduledID
		}
		if current, e := s.DiskPolicy(policyID); e == nil && current.SupersededAt == nil {
			if active, _, _, e := CanonicalDiskPolicy(current.Body); e == nil {
				for _, mount := range active.DataMounts {
					allowed[mount] = true
				}
			}
		}
		for _, mount := range envelope.Operation.Mounts {
			if !allowed[mount.Mount] {
				if out.IgnoredMounts < 32 {
					out.IgnoredMounts++
				}
				continue
			}
			if mount.TotalBytes <= 0 || mount.AvailableBytes < 0 || mount.AvailableBytes > mount.TotalBytes || mount.Percent < 0 || mount.Percent > 100 || len(mount.Mount) > 128 || mount.Mount == "" {
				continue
			}
			mount.MeasuredAt = envelope.Summary.TS
			found := false
			for i, existing := range out.Mounts {
				if existing.Mount == mount.Mount {
					found = true
					old, _ := time.Parse(time.RFC3339, existing.MeasuredAt)
					fresh, _ := time.Parse(time.RFC3339, mount.MeasuredAt)
					if fresh.After(old) {
						out.Mounts[i] = mount
					}
					break
				}
			}
			if !found && len(out.Mounts) < 16 {
				out.Mounts = append(out.Mounts, mount)
			}
		}
		if script == "disk-safe-clean-v2" {
			out.LastSafeTier = &envelope
			out.Thresholds = policy.Thresholds
			for name, c := range envelope.Summary.Categories {
				if c.Status == "skipped" {
					out.Skips[name] = c.Note
				}
			}
		} else {
			out.Preview = &envelope
			if out.LastSafeTier == nil {
				out.Thresholds = policy.Thresholds
			}
		}
	}
	for _, scope := range []string{"user", "root"} {
		v, e := s.DiskOwnershipGet(id, scope)
		if e != nil {
			return out, e
		}
		out.Ownership[scope] = v.State
		out.OwnershipRecords = append(out.OwnershipRecords, v)
	}
	if out.LastSafeTier == nil && out.Preview == nil {
		p, e := s.diskCanaryPolicy(id, "user")
		if e != nil {
			return out, e
		}
		out.Thresholds = p.Thresholds
	}
	out.Canary = map[string]DiskCanary{}
	for _, scope := range []string{"user", "root"} {
		v, e := s.DiskCanaryGet(id, scope, s.now().UTC())
		if e != nil {
			return out, e
		}
		out.Canary[scope] = v
	}
	out.Supervision, err = s.DiskSupervision(id)
	if err != nil {
		return out, err
	}
	out.Alerts, err = s.DiskAlertsList(id)
	if err != nil {
		return out, err
	}
	out.Growth, err = s.DiskGrowthRead(id)
	if err != nil {
		return out, err
	}
	for i := range out.Mounts {
		for j := range out.Growth {
			if out.Mounts[i].Mount == out.Growth[j].Mount {
				out.Mounts[i].Growth = &out.Growth[j]
			}
		}
	}
	out.Actions, err = s.DiskActionMetrics(id, s.now().UTC())
	return out, err
}

func diskUsagePercent(total, available int64) int {
	used := new(big.Int).Mul(big.NewInt(total-available), big.NewInt(100))
	return int(used.Quo(used, big.NewInt(total)).Int64())
}
