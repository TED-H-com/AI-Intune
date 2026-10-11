package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/clientip"
)

var ErrServiceToken = errors.New("service token rejected")
var serviceName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)

type ServiceToken struct {
	RotationChainID      string     `json:"rotation_chain_id"`
	RotatedFrom          string     `json:"rotated_from,omitempty"`
	RotatedAt            *time.Time `json:"rotated_at,omitempty"`
	OverlapDeadline      *time.Time `json:"overlap_deadline,omitempty"`
	ChainCreatedAt       time.Time  `json:"chain_created_at"`
	IssueLifetimeSeconds int64      `json:"-"`
	MaxLifetimeSeconds   int64      `json:"-"`
	ID                   string     `json:"id"`
	Name                 string     `json:"name"`
	Scope                string     `json:"scope"`
	Allowlist            []string   `json:"allowlist"`
	SourceCIDRs          []string   `json:"source_cidrs"`
	CreatedBy            string     `json:"created_by"`
	CreatedAt            time.Time  `json:"created_at"`
	ExpiresAt            time.Time  `json:"expires_at"`
	LastUsedAt           *time.Time `json:"last_used_at,omitempty"`
	RevokedAt            *time.Time `json:"revoked_at,omitempty"`
}

func ValidServiceSecret(secret string) bool {
	if len(secret) != 68 || !strings.HasPrefix(secret, "cst_") {
		return false
	}
	_, err := hex.DecodeString(secret[4:])
	return err == nil
}

func (s *Store) CreateServiceToken(t ServiceToken, actor string) (ServiceToken, string, error) {
	now := s.now().UTC()
	if !serviceName.MatchString(t.Name) || (t.Scope != "view" && t.Scope != "operate") || !t.ExpiresAt.After(now) || t.ExpiresAt.After(now.Add(90*24*time.Hour)) || (t.MaxLifetimeSeconds != 0 && t.MaxLifetimeSeconds != 180*86400 && t.MaxLifetimeSeconds != 365*86400) || len(t.Allowlist) == 0 || len(t.Allowlist) > 128 || len(t.SourceCIDRs) > 32 {
		return ServiceToken{}, "", ErrServiceToken
	}
	for _, v := range t.Allowlist {
		if !validServiceRoute(v) || (t.Scope != "operate" && (v == "POST /v1/operator/script-runs/preview" || v == "POST /v1/operator/script-runs")) {
			return ServiceToken{}, "", ErrServiceToken
		}
	}
	for _, v := range t.SourceCIDRs {
		if _, err := netip.ParsePrefix(v); err != nil {
			return ServiceToken{}, "", ErrServiceToken
		}
	}
	tx, err := s.beginWrite(context.Background(), "create_service_token")
	if err != nil {
		return ServiceToken{}, "", err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_accounts WHERE account_id=? AND role='admin' AND disabled_at IS NULL`, actor).Scan(&n); err != nil || n != 1 {
		return ServiceToken{}, "", ErrServiceToken
	}
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return ServiceToken{}, "", err
	}
	secret := "cst_" + hex.EncodeToString(b[:])
	hash := sha256.Sum256([]byte(secret))
	t.ID, err = newHubAccountID()
	if err != nil {
		return ServiceToken{}, "", err
	}
	t.RotationChainID = t.ID
	t.ChainCreatedAt = now
	t.IssueLifetimeSeconds = int64(t.ExpiresAt.Sub(now).Seconds())
	t.CreatedBy = actor
	t.CreatedAt = now
	t.LastUsedAt = nil
	t.RevokedAt = nil
	a, _ := json.Marshal(t.Allowlist)
	c, _ := json.Marshal(t.SourceCIDRs)
	_, err = tx.Exec(`INSERT INTO service_tokens(id,name,scope,token_hash,allowlist,source_cidrs,created_by,created_at,expires_at,rotation_chain_id,chain_created_at,issue_lifetime_seconds,max_lifetime_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`, t.ID, t.Name, t.Scope, hash[:], string(a), string(c), actor, now.Format(time.RFC3339Nano), t.ExpiresAt.UTC().Format(time.RFC3339Nano), t.RotationChainID, now.Format(time.RFC3339Nano), t.IssueLifetimeSeconds, t.MaxLifetimeSeconds)
	if err != nil {
		return ServiceToken{}, "", ErrServiceToken
	}
	err = s.recordAuditTx(tx, AuditEntry{Action: "service-token-create", AuthSubject: "local-user:" + actor, AuthMethod: "local-account-session", Subject: t.ID, OK: true})
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return ServiceToken{}, "", err
	}
	return t, secret, nil
}

const serviceTokenColumns = "id,name,scope,allowlist,source_cidrs,created_by,created_at,expires_at,last_used_at,revoked_at,rotation_chain_id,rotated_from,rotated_at,overlap_deadline,chain_created_at,issue_lifetime_seconds,max_lifetime_seconds"

// ListServiceTokens returns at most 201 entries; the UI shows 200 and reports truncation.
func (s *Store) ListServiceTokens() ([]ServiceToken, error) {
	rows, err := s.rdb.Query("SELECT " + serviceTokenColumns + " FROM service_tokens ORDER BY created_at DESC,id LIMIT 201")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ServiceToken{}
	for rows.Next() {
		t, err := scanServiceToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func scanServiceToken(row rowScanner) (ServiceToken, error) {
	var t ServiceToken
	var a, c, created, expires string
	var used, revoked, rotated, overlap *string
	var chainCreated string
	if err := row.Scan(&t.ID, &t.Name, &t.Scope, &a, &c, &t.CreatedBy, &created, &expires, &used, &revoked, &t.RotationChainID, &t.RotatedFrom, &rotated, &overlap, &chainCreated, &t.IssueLifetimeSeconds, &t.MaxLifetimeSeconds); err != nil {
		return t, err
	}
	if json.Unmarshal([]byte(a), &t.Allowlist) != nil || json.Unmarshal([]byte(c), &t.SourceCIDRs) != nil {
		return t, ErrServiceToken
	}
	var err error
	t.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
	if err != nil {
		return t, ErrServiceToken
	}
	t.ExpiresAt, err = time.Parse(time.RFC3339Nano, expires)
	if err != nil {
		return t, ErrServiceToken
	}
	if used != nil {
		v, e := time.Parse(time.RFC3339Nano, *used)
		if e != nil {
			return t, ErrServiceToken
		}
		t.LastUsedAt = &v
	}
	if revoked != nil {
		v, e := time.Parse(time.RFC3339Nano, *revoked)
		if e != nil {
			return t, ErrServiceToken
		}
		t.RevokedAt = &v
	}
	t.ChainCreatedAt, err = time.Parse(time.RFC3339Nano, chainCreated)
	if err != nil {
		return t, ErrServiceToken
	}
	for raw, dst := range map[*string]**time.Time{rotated: &t.RotatedAt, overlap: &t.OverlapDeadline} {
		if raw != nil {
			v, e := time.Parse(time.RFC3339Nano, *raw)
			if e != nil {
				return t, ErrServiceToken
			}
			*dst = &v
		}
	}
	return t, nil
}

func (s *Store) RevokeServiceToken(id, actor string) error {
	tx, err := s.beginWrite(context.Background(), "revoke_service_token")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err = tx.QueryRow(`SELECT count(*) FROM hub_accounts WHERE account_id=? AND role='admin' AND disabled_at IS NULL`, actor).Scan(&n); err != nil || n != 1 {
		return ErrServiceToken
	}
	res, err := tx.Exec(`UPDATE service_tokens SET revoked_at=COALESCE(revoked_at,?) WHERE rotation_chain_id=(SELECT rotation_chain_id FROM service_tokens WHERE id=?)`, s.now().UTC().Format(time.RFC3339Nano), id)
	if err != nil {
		return err
	}
	nrows, _ := res.RowsAffected()
	if nrows < 1 {
		return ErrServiceToken
	}
	err = s.recordAuditTx(tx, AuditEntry{Action: "service-token-revoke", AuthSubject: "local-user:" + actor, AuthMethod: "local-account-session", Subject: id, OK: true})
	if err != nil {
		return err
	}
	return tx.Commit()
}

// AuthenticateServiceToken checks current database state on every request; no cache delays revocation.
func (s *Store) AuthenticateServiceToken(secret, route, peer string, required string) (ServiceToken, error) {
	if !ValidServiceSecret(secret) {
		return ServiceToken{}, ErrServiceToken
	}
	hash := sha256.Sum256([]byte(secret))
	var stored []byte
	var id string
	if err := s.rdb.QueryRow(`SELECT id,token_hash FROM service_tokens WHERE token_hash=?`, hash[:]).Scan(&id, &stored); err != nil || subtle.ConstantTimeCompare(hash[:], stored) != 1 {
		return ServiceToken{}, ErrServiceToken
	}
	t, err := scanServiceToken(s.rdb.QueryRow("SELECT "+serviceTokenColumns+" FROM service_tokens WHERE id=?", id))
	if err != nil {
		return ServiceToken{}, ErrServiceToken
	}
	if !serviceName.MatchString(t.Name) || len(t.Allowlist) == 0 || len(t.Allowlist) > 128 {
		return ServiceToken{}, ErrServiceToken
	}
	if (required != "view" && required != "operate") || (t.Scope != "view" && t.Scope != "operate") || (required == "operate" && t.Scope != "operate") || t.RevokedAt != nil || (t.OverlapDeadline != nil && !t.OverlapDeadline.After(s.now())) || !t.ExpiresAt.After(s.now()) || t.ExpiresAt.After(t.CreatedAt.Add(90*24*time.Hour)) {
		return t, ErrServiceToken
	}
	for _, route := range t.Allowlist {
		if !validServiceRoute(route) {
			return t, ErrServiceToken
		}
	}
	if len(t.Allowlist) > 0 && route != "GET /v1/operator/service-tokens/self" && route != "POST /v1/operator/service-tokens/rotate" {
		found := false
		for _, v := range t.Allowlist {
			if v == route {
				found = true
			}
		}
		if !found {
			return t, ErrServiceToken
		}
	}
	if len(t.SourceCIDRs) > 0 {
		ip, err := netip.ParseAddr(peer)
		if err != nil {
			return t, ErrServiceToken
		}
		found := false
		for _, v := range t.SourceCIDRs {
			p, e := netip.ParsePrefix(v)
			if e == nil && p.Contains(ip.Unmap()) {
				found = true
			}
		}
		if !found {
			return t, ErrServiceToken
		}
	}
	res, err := (boundExec{s: s, name: "use_service_token"}).Exec(`UPDATE service_tokens SET last_used_at=? WHERE id=? AND revoked_at IS NULL AND (overlap_deadline IS NULL OR julianday(overlap_deadline)>julianday(?)) AND scope=? AND julianday(expires_at)>julianday(?)`, s.now().UTC().Format(time.RFC3339Nano), id, s.now().UTC().Format(time.RFC3339Nano), t.Scope, s.now().UTC().Format(time.RFC3339Nano))
	if err != nil {
		return ServiceToken{}, err
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		return t, ErrServiceToken
	}
	return t, nil
}

var serviceRoute = regexp.MustCompile(`^(GET|HEAD|POST|PUT|PATCH|DELETE) /v1/operator/[A-Za-z0-9_{}./$-]+$`)

// Validate using the same ServeMux pattern parser as the Hub, without accepting
// a malformed method, whitespace, query, fragment, or wildcard pattern.
func validServiceRoute(route string) (valid bool) {
	if len(route) > 256 || !serviceRoute.MatchString(route) {
		return false
	}
	defer func() {
		if recover() != nil {
			valid = false
		}
	}()
	http.NewServeMux().Handle(route, http.NotFoundHandler())
	return true
}

var ErrServiceTokenRotated = errors.New("service token already rotated")
var ErrServiceTokenMaxLifetime = errors.New("service token maximum lifetime reached")
var ErrServiceTokenRateLimit = errors.New("service token rotation rate limited")

func (t ServiceToken) MaxExpiry() *time.Time {
	if t.MaxLifetimeSeconds == 0 {
		return nil
	}
	v := t.ChainCreatedAt.Add(time.Duration(t.MaxLifetimeSeconds) * time.Second)
	return &v
}

func (t ServiceToken) Status() string {
	if t.RevokedAt != nil {
		return "revoked"
	}
	if t.RotatedAt != nil {
		return "rotated"
	}
	if !t.ExpiresAt.After(time.Now()) {
		return "expired"
	}
	return "active"
}

// RotateServiceToken serializes chain transitions and persists hourly budgets,
// including the resolved source address. Authentication applies CIDRs before entry.
func (s *Store) RotateServiceToken(id, source string) (ServiceToken, string, error) {
	tx, err := s.beginWrite(context.Background(), "rotate_service_token")
	if err != nil {
		return ServiceToken{}, "", err
	}
	defer tx.Rollback()
	t, err := scanServiceToken(tx.QueryRow("SELECT "+serviceTokenColumns+" FROM service_tokens WHERE id=?", id))
	if err != nil {
		return t, "", ErrServiceToken
	}
	now := s.now().UTC()
	if t.RevokedAt != nil || !t.ExpiresAt.After(now) {
		return t, "", ErrServiceToken
	}
	sourceKey := clientip.Key(source)
	reissue := false
	overlap := now.Add(10 * time.Minute)
	if t.RotatedAt != nil {
		if t.OverlapDeadline == nil || !t.OverlapDeadline.After(now) {
			return t, "", ErrServiceTokenRotated
		}
		successor, e := scanServiceToken(tx.QueryRow("SELECT "+serviceTokenColumns+" FROM service_tokens WHERE rotation_chain_id=? AND rotated_from=? AND revoked_at IS NULL AND rotated_at IS NULL", t.RotationChainID, id))
		if e != nil || successor.LastUsedAt != nil {
			return t, "", ErrServiceTokenRotated
		}
		reissue = true
		overlap = *t.OverlapDeadline // Recovery never extends the predecessor's window.
	} else if t.RotatedFrom != "" {
		var deadline *string
		if err = tx.QueryRow("SELECT overlap_deadline FROM service_tokens WHERE id=?", t.RotatedFrom).Scan(&deadline); err != nil {
			return t, "", ErrServiceTokenRotated
		}
		if deadline == nil {
			return t, "", ErrServiceTokenRotated
		}
		end, e := time.Parse(time.RFC3339Nano, *deadline)
		if e != nil || end.After(now) {
			return t, "", ErrServiceTokenRotated
		}
	}
	// Enforce newest membership even for legacy chains with several live generations.
	var newer int
	if err = tx.QueryRow("SELECT count(*) FROM service_tokens WHERE rotation_chain_id=? AND rotated_from=? AND revoked_at IS NULL", t.RotationChainID, id).Scan(&newer); err != nil {
		return t, "", err
	}
	if !reissue && newer != 0 {
		return t, "", ErrServiceTokenRotated
	}
	keys := []string{"chain:" + t.RotationChainID, "ip:" + sourceKey}
	for i, key := range keys {
		var n int
		query := "SELECT count(*) FROM service_token_rotations WHERE budget_key=? AND julianday(created_at)>julianday(?)"
		args := []any{key, now.Add(-time.Hour).Format(time.RFC3339Nano)}
		if i == 0 {
			query = "SELECT count(*) FROM service_token_rotations WHERE (budget_key=? OR budget_key IN (SELECT 'token:'||id FROM service_tokens WHERE rotation_chain_id=?)) AND julianday(created_at)>julianday(?)"
			args = []any{key, t.RotationChainID, now.Add(-time.Hour).Format(time.RFC3339Nano)}
		}
		if err = tx.QueryRow(query, args...).Scan(&n); err != nil {
			return t, "", err
		}
		if n >= 3 {
			return t, "", ErrServiceTokenRateLimit
		}
	}
	expires := now.Add(time.Duration(t.IssueLifetimeSeconds) * time.Second)
	if expires.After(now.Add(90 * 24 * time.Hour)) {
		expires = now.Add(90 * 24 * time.Hour)
	}
	if max := t.MaxExpiry(); max != nil {
		if !max.After(now) {
			return t, "", ErrServiceTokenMaxLifetime
		}
		if expires.After(*max) {
			expires = *max
		}
	}
	var b [32]byte
	if _, err = rand.Read(b[:]); err != nil {
		return t, "", err
	}
	secret := "cst_" + hex.EncodeToString(b[:])
	hash := sha256.Sum256([]byte(secret))
	nextID, err := newHubAccountID()
	if err != nil {
		return t, "", err
	}
	a, _ := json.Marshal(t.Allowlist)
	c, _ := json.Marshal(t.SourceCIDRs)
	_, err = tx.Exec(`INSERT INTO service_tokens(id,name,scope,token_hash,allowlist,source_cidrs,created_by,created_at,expires_at,rotation_chain_id,rotated_from,chain_created_at,issue_lifetime_seconds,max_lifetime_seconds) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, nextID, t.Name, t.Scope, hash[:], string(a), string(c), t.CreatedBy, now.Format(time.RFC3339Nano), expires.Format(time.RFC3339Nano), t.RotationChainID, id, t.ChainCreatedAt.Format(time.RFC3339Nano), t.IssueLifetimeSeconds, t.MaxLifetimeSeconds)
	if err != nil {
		return t, "", err
	}
	_, err = tx.Exec("UPDATE service_tokens SET rotated_at=COALESCE(rotated_at,?),overlap_deadline=? WHERE id=?", now.Format(time.RFC3339Nano), overlap.Format(time.RFC3339Nano), id)
	if err != nil {
		return t, "", err
	}
	// Retain only the new credential and its immediate predecessor.
	if _, err = tx.Exec("UPDATE service_tokens SET revoked_at=COALESCE(revoked_at,?) WHERE rotation_chain_id=? AND id NOT IN (?,?)", now.Format(time.RFC3339Nano), t.RotationChainID, id, nextID); err != nil {
		return t, "", err
	}
	for _, key := range keys {
		if _, err = tx.Exec("INSERT INTO service_token_rotations(budget_key,created_at) VALUES(?,?)", key, now.Format(time.RFC3339Nano)); err != nil {
			return t, "", err
		}
	}
	if _, err = tx.Exec("DELETE FROM service_token_rotations WHERE julianday(created_at)<=julianday(?)", now.Add(-time.Hour).Format(time.RFC3339Nano)); err != nil {
		return t, "", err
	}
	action := AuditAction("service-token-rotate")
	if reissue {
		action = "service-token-reissue"
	}
	err = s.recordAuditTx(tx, AuditEntry{Action: action, AuthSubject: "service:" + t.Name, AuthMethod: "service-token", Subject: id, SourceAddr: source, OK: true, Detail: "rotated to " + nextID})
	if err != nil {
		return t, "", err
	}
	if err = tx.Commit(); err != nil {
		return t, "", err
	}
	t.ID = nextID
	t.RotatedFrom = id
	t.CreatedAt = now
	t.ExpiresAt = expires
	t.LastUsedAt = nil
	t.RotatedAt = nil
	t.OverlapDeadline = nil
	return t, secret, nil
}
