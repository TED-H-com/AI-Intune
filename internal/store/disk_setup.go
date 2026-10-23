package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"time"
)

type DiskSetupRecord struct {
	Job       model.DiskJob       `json:"job"`
	State     string              `json:"state"`
	CreatedAt time.Time           `json:"created_at"`
	Result    model.DiskJobResult `json:"result"`
}
type MachineDisks struct {
	Devices []model.BlockDevice `json:"devices"`
	Jobs    []DiskSetupRecord   `json:"jobs"`
}

func (s *Store) MachineDisks(machine string) (MachineDisks, error) {
	out := MachineDisks{Devices: []model.BlockDevice{}, Jobs: []DiskSetupRecord{}}
	if _, e := s.GetMachine(machine); e != nil {
		return out, e
	}
	var raw string
	e := s.rdb.QueryRow(`SELECT payload FROM observed_latest WHERE machine_id=? AND kind='block_devices' ORDER BY received_at DESC,measured_at DESC,observation_sequence DESC LIMIT 1`, machine).Scan(&raw)
	if e != nil && !errors.Is(e, sql.ErrNoRows) {
		return out, e
	}
	if e == nil {
		if e = json.Unmarshal([]byte(raw), &out.Devices); e != nil {
			return out, e
		}
	}
	rows, e := s.rdb.Query(`SELECT job,state,created_at,result,expires_at FROM disk_setup_jobs WHERE machine_id=? ORDER BY created_at DESC,id DESC`, machine)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		var j DiskSetupRecord
		var body, result, created, expires string
		if e = rows.Scan(&body, &j.State, &created, &result, &expires); e != nil {
			return out, e
		}
		if e = json.Unmarshal([]byte(body), &j.Job); e != nil {
			return out, e
		}
		if e = json.Unmarshal([]byte(result), &j.Result); e != nil {
			return out, e
		}
		j.CreatedAt = parseTime(created)
		if j.State == "pending" && !parseTime(expires).After(s.now()) {
			j.State = "expired"
		}
		out.Jobs = append(out.Jobs, j)
	}
	return out, rows.Err()
}
func (s *Store) ApproveDiskSetup(machine string, j model.DiskJob, a AuditEntry) (string, error) {
	j.ID = newID()
	if e := j.Validate(); e != nil {
		return "", e
	}
	tx, e := s.beginWrite(context.Background(), "disk_setup_approve")
	if e != nil {
		return "", e
	}
	defer tx.Rollback()
	var osName string
	if e = tx.QueryRow(`SELECT os FROM machine_registry WHERE machine_id=?`, machine).Scan(&osName); e != nil || osName != "linux" {
		return "", fmt.Errorf("Disk setup requires a Linux machine")
	}
	var raw string
	if e = tx.QueryRow(`SELECT payload FROM observed_latest WHERE machine_id=? AND kind='block_devices' ORDER BY received_at DESC,measured_at DESC,observation_sequence DESC LIMIT 1`, machine).Scan(&raw); e != nil {
		return "", fmt.Errorf("Disk inventory is unavailable")
	}
	var disks []model.BlockDevice
	if json.Unmarshal([]byte(raw), &disks) != nil {
		return "", fmt.Errorf("Disk inventory is unavailable")
	}
	found := false
	for _, d := range disks {
		if d.Path == j.Device && model.UnusedDisk(d) && d.Serial == j.Serial && d.WWN == j.WWN && d.SizeBytes == j.SizeBytes && d.Model == j.Model {
			found = true
		}
	}
	if !found {
		return "", fmt.Errorf("This disk is no longer ready to set up")
	}
	now := s.now().UTC()
	if _, e = tx.Exec(`UPDATE disk_setup_jobs SET state='expired' WHERE state='pending' AND expires_at<=?`, fmtTime(now)); e != nil {
		return "", e
	}
	body, _ := json.Marshal(j)
	if _, e = tx.Exec(`INSERT INTO disk_setup_jobs(id,machine_id,device,serial,wwn,job,state,created_at,expires_at) VALUES(?,?,?,?,?,?,'pending',?,?)`, j.ID, machine, j.Device, j.Serial, j.WWN, string(body), fmtTime(now), fmtTime(now.Add(24*time.Hour))); e != nil {
		return "", fmt.Errorf("This disk already has an active setup job")
	}
	a.Action = "disk_setup_approve"
	a.Subject = j.ID
	a.MachineID = machine
	a.OK = true
	if e = s.recordAudit(tx, a); e != nil {
		return "", e
	}
	return j.ID, tx.Commit()
}
func (s *Store) CancelDiskSetup(machine, id string, a AuditEntry) error {
	tx, e := s.beginWrite(context.Background(), "disk_setup_cancel")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	r, e := tx.Exec(`UPDATE disk_setup_jobs SET state='expired' WHERE id=? AND machine_id=? AND state='pending' AND expires_at>?`, id, machine, fmtTime(s.now().UTC()))
	if e != nil {
		return e
	}
	n, _ := r.RowsAffected()
	if n != 1 {
		return fmt.Errorf("Only a pending disk setup can be cancelled")
	}
	a.Action = "disk_setup_cancel"
	a.Subject = id
	a.MachineID = machine
	a.OK = true
	if e = s.recordAudit(tx, a); e != nil {
		return e
	}
	return tx.Commit()
}
func (s *Store) DeliverDiskJobs(machine string) ([]model.DiskJob, error) {
	out := []model.DiskJob{}
	tx, e := s.beginWrite(context.Background(), "disk_setup_delivery")
	if e != nil {
		return nil, e
	}
	defer tx.Rollback()
	if _, e = tx.Exec(`UPDATE disk_setup_jobs SET state='expired' WHERE machine_id=? AND state='pending' AND expires_at<=?`, machine, fmtTime(s.now().UTC())); e != nil {
		return nil, e
	}
	rows, e := tx.Query(`SELECT job FROM disk_setup_jobs WHERE machine_id=? AND state IN ('pending','delivered') ORDER BY created_at,id LIMIT 128`, machine)
	if e != nil {
		return nil, e
	}
	for rows.Next() {
		var raw string
		if e = rows.Scan(&raw); e != nil {
			rows.Close()
			return nil, e
		}
		var j model.DiskJob
		if e = json.Unmarshal([]byte(raw), &j); e != nil {
			rows.Close()
			return nil, e
		}
		out = append(out, j)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return nil, e
	}
	for _, j := range out {
		if _, e = tx.Exec(`UPDATE disk_setup_jobs SET state='delivered' WHERE id=? AND state='pending'`, j.ID); e != nil {
			return nil, e
		}
	}
	return out, tx.Commit()
}

// Results are bound to both the authenticated machine and delivered job. The
// terminal transition and its audit row share the observation transaction.
type preparedDiskSetupResult struct {
	result model.DiskJobResult
	body   string
}

func prepareDiskSetupResults(results []model.DiskJobResult) ([]preparedDiskSetupResult, error) {
	if len(results) > 128 {
		return nil, fmt.Errorf("Too many disk setup results")
	}
	prepared := make([]preparedDiskSetupResult, 0, len(results))
	for _, r := range results {
		if !r.Valid() {
			return nil, fmt.Errorf("Invalid disk setup result")
		}
		body, err := json.Marshal(r)
		if err != nil {
			return nil, err
		}
		prepared = append(prepared, preparedDiskSetupResult{r, string(body)})
	}
	return prepared, nil
}

func (s *Store) recordDiskSetupResults(tx dbTx, machine string, results []model.DiskJobResult, now time.Time) error {
	prepared, err := prepareDiskSetupResults(results)
	if err != nil {
		return err
	}
	return s.recordPreparedDiskSetupResults(tx, machine, prepared, now)
}

func (s *Store) recordPreparedDiskSetupResults(tx dbTx, machine string, results []preparedDiskSetupResult, now time.Time) error {
	for _, prepared := range results {
		r, body := prepared.result, prepared.body
		changed, e := tx.Exec(`UPDATE disk_setup_jobs SET state=?,result=? WHERE id=? AND machine_id=? AND state='delivered'`, r.State, string(body), r.ID, machine)
		if e != nil {
			return e
		}
		n, _ := changed.RowsAffected()
		if n == 0 {
			continue
		}
		if e = s.recordAudit(tx, AuditEntry{At: now, Action: "disk_setup_result", MachineID: machine, Subject: r.ID, OK: true}); e != nil {
			return e
		}
	}
	return nil
}
