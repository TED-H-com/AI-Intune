package store

import (
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/schedulecron"
	"github.com/teddashh/AI-Intune/internal/scheduledcheck"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/state"
)

// ScheduledChecks optionally limits results to enabled schedules. Manual runs and unrelated jobs
// cannot replace scheduled evidence. History is bounded per target, not across
// the fleet, so a busy target cannot hide another target's failures.
func (s *Store) ScheduledChecks(since, now time.Time, enabledOnly bool) ([]scheduledcheck.Schedule, error) {
	schedules, err := s.ScheduleList()
	if err != nil {
		return nil, err
	}
	out := []scheduledcheck.Schedule{}
	for _, v := range schedules {
		if enabledOnly && !v.Enabled {
			continue
		}
		cron, err := schedulecron.Parse(v.Cron)
		if err != nil {
			return nil, err
		}
		// Configuration changes reset the due-time baseline. Earlier target lists
		// and enable/disable intervals are not reconstructable from current config.
		start := since
		if v.UpdatedAt.After(start) {
			start = v.UpdatedAt
		}
		var due time.Time
		for next := scheduleNext(cron, start, v.TZ); v.Enabled && !next.IsZero() && !next.After(now); next = scheduleNext(cron, next, v.TZ) {
			due = next
		}
		group := scheduledcheck.Schedule{ID: v.ID, Name: scheduledcheck.Text(v.Name, 100), ScriptID: v.ScriptID}
		for _, machine := range v.Targets {
			result, err := s.scheduledTarget(v, machine, due, since, now, cron)
			if err != nil {
				return nil, err
			}
			group.Targets = append(group.Targets, result)
		}
		out = append(out, group)
	}
	return out, nil
}

func (s *Store) scheduledTarget(v Schedule, machine string, due, since, now time.Time, cron *schedulecron.Cron) (scheduledcheck.Result, error) {
	result := scheduledcheck.Result{MachineID: machine, Status: "not_run", At: due, InWindow: !due.IsZero(), Reason: "No scheduled run was received."}
	var name string
	if err := s.rdb.QueryRow(`SELECT COALESCE(NULLIF(display_name,''),machine_id) FROM machine_registry WHERE machine_id=?`, machine).Scan(&name); err != nil {
		return result, err
	}
	result.DisplayName = scheduledcheck.Text(name, 100)
	rows, err := s.rdb.Query(`SELECT sj.slot,j.state,COALESCE(j.terminal_at,''),
 COALESCE((SELECT substr(vr.stderr_excerpt,1,8192) FROM verification_results vr
 WHERE vr.job_id=j.job_id AND vr.machine_id=j.machine_id AND vr.evidence_role='executor'
 AND (vr.passed=0 OR vr.exit_code<>0) ORDER BY vr.received_at DESC,vr.verified_at DESC,vr.verification_id DESC LIMIT 1),''),
 COALESCE((SELECT substr(json_extract(e.payload,'$.detail'),1,8192) FROM job_events e
 WHERE e.job_id=j.job_id AND e.evidence_role='executor' AND json_valid(e.payload)
 AND json_type(e.payload,'$.detail')='text' ORDER BY e.seq DESC LIMIT 1),'')
 FROM schedule_jobs sj JOIN jobs j ON j.job_id=sj.job_id
 JOIN desired_state d ON d.desired_id=j.desired_id
 WHERE sj.schedule_id=? AND j.machine_id=? AND d.resource_kind=?
 AND json_valid(d.spec) AND json_extract(d.spec,'$.script_id')=?
 AND sj.slot NOT LIKE 'manual:%'
 AND julianday(sj.slot)<=julianday(?)
 ORDER BY julianday(sj.slot) DESC,j.created_at DESC,j.job_id DESC LIMIT ?`, v.ID, machine, scriptcatalog.Kind, v.ScriptID, fmtTime(now), scheduledcheck.HistoryLimit)
	if err != nil {
		return result, err
	}
	defer rows.Close()
	var previous time.Time
	streak := true
	first := true
	for rows.Next() {
		var slot, terminal, stderr, detail string
		var jobState deploy.JobState
		if err := rows.Scan(&slot, &jobState, &terminal, &stderr, &detail); err != nil {
			return result, err
		}
		at, err := time.Parse(time.RFC3339Nano, slot)
		if err != nil {
			return result, err
		}
		if first {
			first = false
			// A newer expected slot without a job must replace an older success.
			if !due.IsZero() && at.Before(due) {
				break
			}
			result.At = at
			if t, err := time.Parse(time.RFC3339Nano, terminal); err == nil {
				result.At = t
			}
			result.InWindow = at.After(since) && !at.Before(v.UpdatedAt)
			switch jobState {
			case deploy.Succeeded:
				result.Status, result.Reason = "passed", ""
			case deploy.Failed, deploy.Rejected, deploy.LeaseExpired, deploy.ManualIntervention:
				result.Status = "failed"
				result.Reason = scheduledcheck.Reason(stderr)
				if result.Reason == "" {
					result.Reason = scheduledcheck.Reason(detail)
				}
				if result.Reason == "" {
					switch jobState {
					case deploy.Rejected:
						result.Reason = "The machine rejected the check."
					case deploy.LeaseExpired:
						result.Reason = "The check did not finish before its time limit."
					default:
						result.Reason = "The check failed without a failure reason."
					}
				}
			default:
				result.Status, result.Reason = "pending", "The scheduled check is waiting for a result."
			}
		}
		// Count only contiguous scheduled failures. A missed slot or a success
		// breaks the streak; manual retries never extend or reset it.
		if streak && (previous.IsZero() || scheduleNext(cron, at, v.TZ).Equal(previous)) &&
			(jobState == deploy.Failed || jobState == deploy.Rejected || jobState == deploy.LeaseExpired || jobState == deploy.ManualIntervention) {
			result.ConsecutiveFailures++
		} else {
			streak = false
		}
		previous = at
	}
	return result, rows.Err()
}

// UntargetedScheduleMachines uses current heartbeat freshness and the latest
// check-in's explicit jobs-enabled signal. Unknown and monitor-only agents are
// excluded, as are retired and non-reporting machines.
func (s *Store) UntargetedScheduleMachines(machines []MachineRow, schedules []scheduledcheck.Schedule, now time.Time) ([]string, error) {
	targeted := map[string]bool{}
	for _, v := range schedules {
		for _, target := range v.Targets {
			targeted[target.MachineID] = true
		}
	}
	names := []string{}
	for _, m := range machines {
		if !m.InDenominator() || !state.IsReportingAt(m.Facts, now) || targeted[m.MachineID] {
			continue
		}
		enabled, err := latestMachineJobsEnabled(s.rdb, m.MachineID)
		if err != nil {
			return nil, err
		}
		if enabled != nil && *enabled {
			names = append(names, scheduledcheck.Text(m.DisplayName, 100))
		}
	}
	return names, nil
}
