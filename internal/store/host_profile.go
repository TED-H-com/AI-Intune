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
	rows, err := s.rdb.Query(`SELECT machine_id,display_name FROM machine_registry WHERE os='linux' ORDER BY display_name,machine_id`)
	if err != nil {
		return v, err
	}
	for rows.Next() {
		var h HostProfileStatus
		if err = rows.Scan(&h.MachineID, &h.DisplayName); err != nil {
			rows.Close()
			return v, err
		}
		v.Hosts = append(v.Hosts, h)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return v, err
	}
	for i := range v.Hosts {
		h := &v.Hosts[i]
		h.Status = "Waiting"
		var raw, recv string
		err = s.rdb.QueryRow(`SELECT payload,received_at FROM observed_latest WHERE machine_id=? AND kind='host_profile_apply' ORDER BY received_at DESC,measured_at DESC,observation_sequence DESC LIMIT 1`, h.MachineID).Scan(&raw, &recv)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return v, err
		}
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
	return v, nil
}
