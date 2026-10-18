package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/teddashh/AI-Intune/internal/model"
	"sort"
)

func (s *Store) FleetReadinessProfile() (model.FleetReadinessProfile, error) {
	var p model.FleetReadinessProfile
	var raw string
	err := s.rdb.QueryRow(`SELECT config FROM fleet_readiness_profile WHERE id=1`).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		// Only an absent profile gets default-on; saved false stays false.
		p.AutoRemediateUserUnits = true
		return p, nil
	}
	if err != nil {
		return p, err
	}
	err = json.Unmarshal([]byte(raw), &p)
	return p, err
}
func (s *Store) SaveFleetReadinessProfile(p model.FleetReadinessProfile, audits ...AuditEntry) error {
	if err := p.Validate(); err != nil {
		return err
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tx, err := s.beginWrite(context.Background(), "fleet_readiness_profile")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO fleet_readiness_profile(id,config) VALUES(1,?) ON CONFLICT(id) DO UPDATE SET config=excluded.config`, string(raw)); err != nil {
		return err
	}
	for _, a := range audits {
		a.Action = AuditAction("fleet_readiness_profile")
		a.Subject = "fleet"
		a.MachineID = ""
		a.OK = true
		if err = s.recordAudit(tx, a); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func (s *Store) EffectiveReadinessConfig(id string) (model.ReadinessConfig, error) {
	c, err := s.HostReadinessConfig(id)
	if err != nil {
		return c, err
	}
	p, err := s.FleetReadinessProfile()
	return p.Effective(c), err
}

// ReadinessMachineIDs avoids building the expensive fleet overview.
func (s *Store) ReadinessMachineIDs() ([]string, error) {
	rows, err := s.rdb.Query(`SELECT machine_id FROM machine_registry WHERE retired_at IS NULL`)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, id := range ids {
		names[id] = s.DisplayName(id)
	}
	sort.Slice(ids, func(i, j int) bool {
		if names[ids[i]] == names[ids[j]] {
			return ids[i] < ids[j]
		}
		return names[ids[i]] < names[ids[j]]
	})
	return ids, nil
}
