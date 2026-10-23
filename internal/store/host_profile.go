package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/teddashh/AI-Intune/internal/model"
	"time"
)

type FleetHostProfile struct {
	Profile model.HostProfile   `json:"profile"`
	Digest  string              `json:"digest"`
	Hosts   []HostProfileStatus `json:"hosts"`
}
type HostProfileStatus struct {
	MachineID   string                 `json:"machine_id"`
	DisplayName string                 `json:"display_name"`
	Status      string                 `json:"status"`
	ReceivedAt  *time.Time             `json:"received_at"`
	Result      *model.HostApplyResult `json:"result"`
}

func (s *Store) HostProfile() (model.HostProfile, error) {
	var raw string
	err := s.rdb.QueryRow(`SELECT profile FROM fleet_host_profile WHERE singleton=1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return model.HostProfile{}, nil
	}
	if err != nil {
		return model.HostProfile{}, err
	}
	return model.ParseHostProfile([]byte(raw))
}
func (s *Store) SaveHostProfile(p model.HostProfile, a AuditEntry) error {
	raw, err := p.Canonical()
	if err != nil {
		return err
	}
	tx, err := s.beginWrite(context.Background(), "fleet_host_profile")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO fleet_host_profile(singleton,profile) VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET profile=excluded.profile`, string(raw)); err != nil {
		return err
	}
	a.Action = AuditAction("fleet_host_profile")
	a.Subject = "fleet"
	a.OK = true
	if err = s.recordAudit(tx, a); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *Store) LinuxMachine(id string) (bool, error) {
	var os string
	err := s.rdb.QueryRow(`SELECT COALESCE(os,'') FROM machine_registry WHERE machine_id=?`, id).Scan(&os)
	return os == "linux", err
}
func (s *Store) FleetHostProfile(now time.Time) (FleetHostProfile, error) {
	v := FleetHostProfile{Hosts: []HostProfileStatus{}}
	var err error
	v.Profile, err = s.HostProfile()
	if err != nil {
		return v, err
	}
	v.Digest, err = v.Profile.Digest()
	if err != nil {
		return v, err
	}
	// Select one observation per host inside the set query. The correlated
	// lookup visits the small current projection, never the retained ledger.
	rows, err := s.rdb.Query(`SELECT m.machine_id,m.display_name,o.payload,o.received_at
 FROM machine_registry m
 LEFT JOIN observed_latest o ON o.machine_id=m.machine_id AND o.kind='host_profile_apply'
 AND o.subject=(SELECT x.subject FROM observed_latest x
   WHERE x.machine_id=m.machine_id AND x.kind='host_profile_apply'
   ORDER BY x.received_at DESC,x.measured_at DESC,x.observation_sequence DESC LIMIT 1)
 WHERE m.os='linux' ORDER BY m.display_name,m.machine_id`)
	if err != nil {
		return v, err
	}
	defer rows.Close()
	for rows.Next() {
		var host HostProfileStatus
		var payload, received sql.NullString
		if err = rows.Scan(&host.MachineID, &host.DisplayName, &payload, &received); err != nil {
			return v, err
		}
		v.Hosts = append(v.Hosts, host)
		h := &v.Hosts[len(v.Hosts)-1]
		h.Status = "Waiting"
		if !payload.Valid {
			continue
		}
		raw, recv := payload.String, received.String
		if json.Unmarshal([]byte(raw), &h.Result) != nil || h.Result == nil {
			continue
		}
		t := parseTime(recv)
		h.ReceivedAt = &t
		if !model.ValidHostApplyResult(h.Result) {
			h.Result = nil
			continue
		}
		if h.Result.ProfileDigest == v.Digest && now.Sub(h.Result.AppliedAt) <= 90*time.Minute && !h.Result.AppliedAt.After(now.Add(time.Minute)) && now.Sub(t) <= 15*time.Minute && !t.After(now.Add(time.Minute)) {
			h.Status = "Up to date"
		}
		for _, item := range h.Result.Items {
			if item.Status == "failed" {
				h.Status = "Failed"
			}
		}
	}
	return v, rows.Err()
}
