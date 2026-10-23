package store

import (
	"database/sql"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

// ReadReportReceipt is source evidence for the operator's allowlisted projection.
// Raw output must never be rendered directly.
type ReadReportReceipt struct {
	ScriptID, JobID, State, RanAt, Output string
	ProcessFailed                         bool
}

func (s *Store) LatestReadReports(machine string) ([]ReadReportReceipt, error) {
	out := []ReadReportReceipt{}
	for _, id := range []string{"oci-cost-report-v1", "network-watch-v1", "bat-release-check-v1"} {
		v := ReadReportReceipt{ScriptID: id}
		err := s.rdb.QueryRow(`SELECT j.job_id,j.state,COALESCE((SELECT COALESCE(NULLIF(v.received_at,''),v.verified_at) FROM verification_results v WHERE v.job_id=j.job_id AND v.machine_id=j.machine_id AND v.rule_id='script_v1' AND v.evidence_role='executor' ORDER BY v.received_at DESC,v.verification_id DESC LIMIT 1),j.terminal_at,''),
   COALESCE((SELECT substr(v.stdout_excerpt,1,65537) FROM verification_results v
    WHERE v.job_id=j.job_id AND v.machine_id=j.machine_id AND v.rule_id=? AND v.evidence_role='executor'
    ORDER BY v.received_at DESC,v.verified_at DESC,v.verification_id DESC LIMIT 1),''),
   COALESCE((SELECT v.exit_code<>0 OR v.passed=0 FROM verification_results v WHERE v.job_id=j.job_id AND v.machine_id=j.machine_id AND v.rule_id='script_v1' AND v.evidence_role='executor' ORDER BY v.received_at DESC,v.verified_at DESC,v.verification_id DESC LIMIT 1),0)
   FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id
   WHERE j.machine_id=? AND d.resource_kind=? AND json_valid(d.spec)
   AND json_extract(d.spec,'$.script_id')=?
   ORDER BY j.created_at DESC,j.job_id DESC LIMIT 1`, scriptcatalog.Kind, machine, scriptcatalog.Kind, id).Scan(&v.JobID, &v.State, &v.RanAt, &v.Output, &v.ProcessFailed)
		if err != nil && err != sql.ErrNoRows {
			return nil, err
		}
		out = append(out, v)
	}
	return out, nil
}
