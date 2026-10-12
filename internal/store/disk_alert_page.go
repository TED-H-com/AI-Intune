package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
)

const DiskAlertsPageSize = 100
const diskAlertPagePriority = `CASE WHEN cleared_at IS NULL AND severity='critical' THEN 0 WHEN cleared_at IS NULL THEN 1 WHEN severity='critical' THEN 2 ELSE 3 END`

type DiskAlertsPage struct {
	Items []DiskAlert
	Next  string
}

// DiskAlertsPageAfter uses a stable priority/id keyset and fetches one lookahead row.
func (s *Store) DiskAlertsPageAfter(after string) (DiskAlertsPage, error) {
	out := DiskAlertsPage{Items: []DiskAlert{}}
	priority, id := -1, ""
	if after != "" {
		if len(after) > 200 || len(after) < 3 || after[1] != ':' || after[0] < '0' || after[0] > '3' {
			return out, scriptBad("invalid disk alerts cursor")
		}
		priority, id = int(after[0]-'0'), after[2:]
	}
	rows, err := s.rdb.Query(`SELECT id,machine_id,condition_key,severity,opened_at,cleared_at,acknowledged_at,acknowledgement_reason,cleared_reason FROM disk_alerts WHERE (`+diskAlertPagePriority+`)>? OR ((`+diskAlertPagePriority+`)=? AND id>?) ORDER BY `+diskAlertPagePriority+`,id LIMIT ?`, priority, priority, id, DiskAlertsPageSize+1)
	if err != nil {
		return out, err
	}
	defer rows.Close()
	for rows.Next() {
		var a DiskAlert
		var opened string
		var cleared, ack sql.NullString
		if err = rows.Scan(&a.ID, &a.MachineID, &a.ConditionKey, &a.Severity, &opened, &cleared, &ack, &a.AcknowledgementReason, &a.ClearedReason); err != nil {
			return out, err
		}
		a.OpenedAt = parseTime(opened)
		a.ClearedAt = parseTimePtr(cleared)
		a.AcknowledgedAt = parseTimePtr(ack)
		out.Items = append(out.Items, a)
	}
	if err = rows.Err(); err != nil {
		return out, err
	}
	if len(out.Items) > DiskAlertsPageSize {
		out.Items = out.Items[:DiskAlertsPageSize]
		out.Next = DiskAlertNotificationCursor(out.Items[len(out.Items)-1])
	}
	return out, nil
}

// DiskAlertMountLabels reads only mount names from the latest authenticated safe
// report for each requested machine. Input and per-machine output are capped.
func (s *Store) DiskAlertMountLabels(machines []string) (map[string][]DiskMountUsage, error) {
	out := map[string][]DiskMountUsage{}
	if len(machines) > DiskAlertsPageSize {
		return nil, fmt.Errorf("too many disk alert machines")
	}
	if len(machines) == 0 {
		return out, nil
	}
	raw, _ := json.Marshal(machines)
	rows, err := s.rdb.Query(`SELECT requested.value,(SELECT json_group_array(json_object('mount',mount)) FROM (SELECT json_extract(value,'$.mount') AS mount FROM json_each(COALESCE((SELECT CASE WHEN json_valid(v.stdout_excerpt) AND length(CAST(v.stdout_excerpt AS BLOB))<=65536 THEN json_extract(v.stdout_excerpt,'$.operation.mounts') ELSE '[]' END FROM jobs j JOIN desired_state d ON d.desired_id=j.desired_id JOIN verification_results v ON v.job_id=j.job_id WHERE j.machine_id=requested.value AND d.resource_kind='script_v1' AND d.resource_id=scripts.id AND v.rule_id='script_v1' AND v.exit_code=0 AND v.passed=1 AND v.evidence_role=? AND v.producer_kind=? AND v.producer_id=requested.value AND v.authority=? ORDER BY v.received_at DESC,v.rowid DESC LIMIT 1),'[]')) WHERE type='object' LIMIT 16)) FROM json_each(?) requested CROSS JOIN (SELECT 'disk-safe-clean-v2' AS id UNION ALL SELECT 'disk-safe-preview-v2') scripts`, JobVerificationRoleExecutor, JobVerificationProducerExecutorAgent, JobVerificationAuthorityMachineLease, string(raw))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var machine, body string
		if err = rows.Scan(&machine, &body); err != nil {
			return nil, err
		}
		var entries []struct {
			Mount string `json:"mount"`
		}
		if json.Unmarshal([]byte(body), &entries) != nil {
			continue
		}
		if _, exists := out[machine]; !exists {
			out[machine] = []DiskMountUsage{}
		}
		for _, entry := range entries {
			if len(out[machine]) >= 16 {
				break
			}
			if len(entry.Mount) == 0 || len(entry.Mount) > 128 || !strings.HasPrefix(entry.Mount, "/") || strings.ContainsAny(entry.Mount, "\x00\r\n") {
				continue
			}
			out[machine] = append(out[machine], DiskMountUsage{Mount: entry.Mount})
		}
	}
	return out, rows.Err()
}
