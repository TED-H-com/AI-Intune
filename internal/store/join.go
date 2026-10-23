package store

import (
	"context"
	"crypto/subtle"
	"errors"
	"time"
)

var ErrJoinFull = errors.New("too many waiting machines")
var ErrJoinState = errors.New("join request is no longer waiting")

type JoinRequest struct {
	Code      string    `json:"join_code"`
	Hostname  string    `json:"hostname"`
	OS        string    `json:"os"`
	Arch      string    `json:"arch"`
	User      string    `json:"user"`
	ClientIP  string    `json:"client_ip"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	State     string    `json:"state"`
}

func (s *Store) StartJoin(j JoinRequest, hash []byte) error {
	tx, err := s.beginWrite(context.Background(), "join_start")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := s.now().UTC()
	if _, err = tx.Exec(`DELETE FROM join_requests WHERE expires_at < ?`, fmtTime(now.Add(-7*24*time.Hour))); err != nil {
		return err
	}
	var count int
	if err = tx.QueryRow(`SELECT count(*) FROM join_requests WHERE state IN ('pending','approved','approval_expired') AND expires_at > ?`, fmtTime(now)).Scan(&count); err != nil {
		return err
	}
	if count >= 20 {
		return ErrJoinFull
	}
	_, err = tx.Exec(`INSERT INTO join_requests VALUES (?,?,?,?,?,?,?,?,?,'pending')`, j.Code, hash, j.Hostname, j.OS, j.Arch, j.User, j.ClientIP, fmtTime(j.CreatedAt), fmtTime(j.ExpiresAt))
	if err != nil {
		return err
	}
	return tx.Commit()
}

func (s *Store) ListJoins(now time.Time) ([]JoinRequest, error) {
	if _, err := s.execWrite(context.Background(), "join_prune", `DELETE FROM join_requests WHERE expires_at < ?`, fmtTime(now.Add(-7*24*time.Hour))); err != nil {
		return nil, err
	}
	rows, err := s.rdb.Query(`SELECT code,hostname,os,arch,user,client_ip,created_at,expires_at,state FROM join_requests WHERE state IN ('pending','approved','approval_expired') AND expires_at > ? ORDER BY created_at,code LIMIT 20`, fmtTime(now))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []JoinRequest{}
	for rows.Next() {
		var j JoinRequest
		var created, expires string
		if err := rows.Scan(&j.Code, &j.Hostname, &j.OS, &j.Arch, &j.User, &j.ClientIP, &created, &expires, &j.State); err != nil {
			return nil, err
		}
		j.CreatedAt, j.ExpiresAt = parseTime(created), parseTime(expires)
		out = append(out, j)
	}
	return out, rows.Err()
}

// LookupJoin compares fixed-size hashes in constant time. The scan is bounded
// by retention and the admission cap; SQL never compares bearer secrets.
func (s *Store) LookupJoin(hash []byte, now time.Time) (JoinRequest, error) {
	rows, err := s.rdb.Query(`SELECT code,secret_hash,hostname,os,arch,user,client_ip,created_at,expires_at,state FROM join_requests WHERE expires_at >= ?`, fmtTime(now.Add(-7*24*time.Hour)))
	if err != nil {
		return JoinRequest{}, err
	}
	defer rows.Close()
	var found JoinRequest
	matched := 0
	for rows.Next() {
		var j JoinRequest
		var h []byte
		var created, expires string
		if err := rows.Scan(&j.Code, &h, &j.Hostname, &j.OS, &j.Arch, &j.User, &j.ClientIP, &created, &expires, &j.State); err != nil {
			return JoinRequest{}, err
		}
		j.CreatedAt, j.ExpiresAt = parseTime(created), parseTime(expires)
		if subtle.ConstantTimeCompare(hash, h) == 1 {
			found = j
			matched = 1
		}
	}
	if err := rows.Err(); err != nil {
		return JoinRequest{}, err
	}
	if matched == 0 {
		return JoinRequest{}, ErrNotFound
	}
	return found, nil
}

// TransitionJoin and the operator decision audit either both commit or neither.
func (s *Store) TransitionJoin(code, from, to string, audit *AuditEntry) error {
	tx, err := s.beginWrite(context.Background(), "join_transition")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE join_requests SET state=? WHERE code=? AND state=? AND expires_at>?`, to, code, from, fmtTime(s.now().UTC()))
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrJoinState
	}
	if audit != nil {
		if err = s.recordAuditTx(tx, *audit); err != nil {
			return err
		}
	}
	return tx.Commit()
}
