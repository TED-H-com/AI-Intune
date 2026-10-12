package store

import (
	"encoding/json"
	"time"
)

type DiskActionMetrics struct {
	QuarantinedBytes  int64  `json:"quarantined_bytes"`
	FreedBytes        int64  `json:"freed_bytes"`
	TTLBacklog        int64  `json:"ttl_backlog"`
	RestoreSuccess    int64  `json:"restore_success"`
	RestoreConflicts  int64  `json:"restore_conflicts"`
	ProtectionDenials int64  `json:"protection_denials"`
	Samples           int64  `json:"samples"`
	Source            string `json:"source"`
}

func (s *Store) DiskActionMetrics(machine string, now time.Time) (DiskActionMetrics, error) {
	out := DiskActionMetrics{Source: "authenticated action receipts; current quarantine and cumulative item outcomes"}
	err := s.rdb.QueryRow(`SELECT COALESCE(SUM(CASE WHEN state IN ('quarantined','restore_pending','needs_recovery') THEN allocated_bytes ELSE 0 END),0),COALESCE(SUM(CASE WHEN state IN ('quarantined','restore_pending','needs_recovery') AND expires_at<=? THEN 1 ELSE 0 END),0),COALESCE(SUM(CASE WHEN state IN ('expired','deleted') THEN allocated_bytes ELSE 0 END),0) FROM disk_quarantine WHERE (?='' OR machine_id=?)`, fmtTime(now), machine, machine).Scan(&out.QuarantinedBytes, &out.TTLBacklog, &out.FreedBytes)
	if err != nil {
		return out, err
	}
	err = s.rdb.QueryRow(`SELECT COUNT(*),COALESCE(SUM(status IN ('restored','recovered_restore')),0),COALESCE(SUM(reason IN ('destination_occupied','needs_recovery')),0),COALESCE(SUM(reason IN ('protected','protected_repository','protection_changed')),0) FROM disk_action_items WHERE (?='' OR machine_id=?)`, machine, machine).Scan(&out.Samples, &out.RestoreSuccess, &out.RestoreConflicts, &out.ProtectionDenials)
	return out, err
}
func (s *Store) DiskReportDecisions(report string) (map[string]string, error) {
	rows, err := s.rdb.Query(`SELECT m.body,a.state FROM ops_manifests m JOIN ops_approvals a ON a.id=m.approval_id WHERE json_extract(m.body,'$.report_id')=? AND a.state IN ('rejected','consumed') ORDER BY a.created_at,a.id`, report)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var body, state string
		if err = rows.Scan(&body, &state); err != nil {
			return nil, err
		}
		var m DiskManifest
		if err = json.Unmarshal([]byte(body), &m); err != nil {
			return nil, err
		}
		for _, i := range m.Items {
			out[i.ID] = m.Action + ": " + state
		}
	}
	return out, rows.Err()
}
