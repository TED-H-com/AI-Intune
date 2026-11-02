package store

import (
	"context"
	"database/sql"
	"net/url"
	"path/filepath"
	"sort"
	"time"
)

type StaleMachineBranch string

const (
	StaleMachineDuplicateOfActive StaleMachineBranch = "duplicate-of-active"
	StaleMachineAbandoned24h      StaleMachineBranch = "abandoned-24h"
)

type StaleMachineCandidate struct {
	MachineID   string               `json:"machine_id"`
	DisplayName string               `json:"display_name"`
	Hostname    string               `json:"hostname"`
	CreatedAt   time.Time            `json:"created_at"`
	Branches    []StaleMachineBranch `json:"branches"`
	DuplicateOf []string             `json:"duplicate_of"`
}

// OpenStaleMachineReadOnly validates an existing ledger without migrating it.
func OpenStaleMachineReadOnly(path string) (*sql.DB, error) {
	if err := ValidateExistingLedger(path); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	u := &url.URL{Scheme: "file", Path: absolute}
	q := u.Query()
	q.Set("mode", "ro")
	q.Add("_pragma", "query_only(1)")
	q.Add("_pragma", "busy_timeout(5000)")
	u.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func (s *Store) StaleMachineCandidates(now time.Time) ([]StaleMachineCandidate, error) {
	return StaleMachineCandidatesFromDB(s.db, now)
}
func (s *Store) StaleMachineCandidate(machineID string, now time.Time) (StaleMachineCandidate, bool, error) {
	candidates, err := staleMachineCandidatesFromDB(s.db, now, machineID)
	for _, c := range candidates {
		if c.MachineID == machineID {
			return c, true, err
		}
	}
	return StaleMachineCandidate{}, false, err
}

// StaleMachineCandidatesFromDB reads a consistent snapshot. Timestamp comparisons
// use parsed instants so offsets and fractional seconds do not affect eligibility.
func StaleMachineCandidatesFromDB(db *sql.DB, now time.Time) ([]StaleMachineCandidate, error) {
	return staleMachineCandidatesFromDB(db, now, "")
}

func staleMachineCandidatesFromDB(db *sql.DB, now time.Time, machineID string) ([]StaleMachineCandidate, error) {
	tx, err := db.BeginTx(context.Background(), &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.Query(`SELECT machine_id,display_name,COALESCE(hostname,''),created_at FROM machine_registry m
 WHERE (?='' OR machine_id=?) AND enrolled_at IS NULL AND retired_at IS NULL AND NOT EXISTS (SELECT 1 FROM machine_checkins c WHERE c.machine_id=m.machine_id)`, machineID, machineID)
	if err != nil {
		return nil, err
	}
	all := []StaleMachineCandidate{}
	for rows.Next() {
		var c StaleMachineCandidate
		var created string
		if err := rows.Scan(&c.MachineID, &c.DisplayName, &c.Hostname, &created); err != nil {
			rows.Close()
			return nil, err
		}
		c.CreatedAt = parseTime(created)
		all = append(all, c)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	result := []StaleMachineCandidate{}
	for _, c := range all {
		if c.CreatedAt.IsZero() || c.CreatedAt.After(now.Add(-time.Hour)) {
			continue
		}
		c.DuplicateOf = []string{}
		duplicates, err := tx.Query(`SELECT machine_id FROM machine_registry a WHERE machine_id<>? AND retired_at IS NULL
 AND EXISTS (SELECT 1 FROM machine_checkins x WHERE x.machine_id=a.machine_id)
 AND ((a.display_name<>'' AND a.display_name IN (NULLIF(?,''),NULLIF(?,''))) OR (a.hostname<>'' AND a.hostname IN (NULLIF(?,''),NULLIF(?,'')))) ORDER BY machine_id`, c.MachineID, c.DisplayName, c.Hostname, c.DisplayName, c.Hostname)
		if err != nil {
			return nil, err
		}
		for duplicates.Next() {
			var id string
			if err := duplicates.Scan(&id); err != nil {
				duplicates.Close()
				return nil, err
			}
			c.DuplicateOf = append(c.DuplicateOf, id)
		}
		err = duplicates.Err()
		duplicates.Close()
		if err != nil {
			return nil, err
		}
		if len(c.DuplicateOf) > 0 {
			c.Branches = append(c.Branches, StaleMachineDuplicateOfActive)
		}
		if !c.CreatedAt.After(now.Add(-24 * time.Hour)) {
			c.Branches = append(c.Branches, StaleMachineAbandoned24h)
		}
		if len(c.Branches) == 0 {
			continue
		}
		pending, err := tx.Query(`SELECT expires_at FROM enrollment_tokens WHERE used_at IS NULL AND (used_by=? OR display_name IN (?,?))
 UNION ALL SELECT expires_at FROM join_requests WHERE state='pending' AND hostname IN (?,?)`, c.MachineID, c.DisplayName, c.Hostname, c.DisplayName, c.Hostname)
		if err != nil {
			return nil, err
		}
		blocked := false
		for pending.Next() {
			var expires string
			if err := pending.Scan(&expires); err != nil {
				pending.Close()
				return nil, err
			}
			if parseTime(expires).After(now) {
				blocked = true
			}
		}
		err = pending.Err()
		pending.Close()
		if err != nil {
			return nil, err
		}
		if !blocked {
			result = append(result, c)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].MachineID < result[j].MachineID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, tx.Commit()
}
