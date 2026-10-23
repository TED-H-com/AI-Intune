package operator

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/tailnet"
)

var ErrJoinRate = errors.New("too many join requests; try again in a minute")
var ErrJoinInput = errors.New("invalid machine details")
var joinHost = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}$`)
var joinWindowsUser = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_. -]{0,62}[a-zA-Z0-9_-]$|^[a-zA-Z0-9_]$`)
var joinUser = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?$`)

type JoinRequestsResult struct {
	Requests []store.JoinRequest `json:"requests"`
}

type JoinStart struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	User     string `json:"user"`
}
type JoinStarted struct {
	Code        string    `json:"join_code"`
	Secret      string    `json:"device_secret"`
	ExpiresAt   time.Time `json:"expires_at"`
	PollSeconds int       `json:"poll_seconds"`
}
type JoinTailnet struct {
	AuthKey  string   `json:"auth_key"`
	Tags     []string `json:"tags"`
	Hostname string   `json:"hostname"`
}
type JoinBundle struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}
type JoinPayload struct {
	MonitorOnly bool         `json:"monitor_only,omitempty"`
	State       string       `json:"state"`
	DisplayName string       `json:"display_name"`
	EnrollToken string       `json:"enroll_token"`
	HubURL      string       `json:"hub_url"`
	Tailscale   *JoinTailnet `json:"tailscale,omitempty"`
	Bundle      JoinBundle   `json:"bundle"`
}
type joinDelivery struct {
	payload JoinPayload
	expires time.Time
}
type joinRate struct {
	at time.Time
	n  int
}
type joinState struct {
	mu       sync.Mutex
	keys     *tailnet.JoinKeys
	payloads map[string]joinDelivery
	rates    map[string]joinRate
}

func (s *Service) joins() *joinState {
	s.joinOnce.Do(func() { s.join = &joinState{payloads: map[string]joinDelivery{}, rates: map[string]joinRate{}} })
	return s.join
}
func (s *Service) ConfigureJoinKeys(keys *tailnet.JoinKeys) {
	j := s.joins()
	j.mu.Lock()
	defer j.mu.Unlock()
	j.keys = keys
}
func (s *Service) JoinKeysConfigured() bool {
	j := s.joins()
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.keys.Configured()
}
func (j *joinState) prune(now time.Time) {
	for k, v := range j.payloads {
		if !now.Before(v.expires) {
			delete(j.payloads, k)
		}
	}
	for k, v := range j.rates {
		if now.Sub(v.at) >= time.Minute {
			delete(j.rates, k)
		}
	}
}
func (s *Service) StartJoin(req JoinStart, ip string) (JoinStarted, error) {
	j := s.joins()
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now().UTC()
	j.prune(now)
	rate := j.rates[ip]
	if rate.n >= 5 || len(j.rates) >= 4096 && rate.n == 0 {
		return JoinStarted{}, ErrJoinRate
	}
	if rate.n == 0 {
		rate.at = now
	}
	rate.n++
	j.rates[ip] = rate
	validUser := req.OS == "linux" && joinUser.MatchString(req.User) && req.User != "root"
	if req.OS == "windows" {
		validUser = joinWindowsUser.MatchString(req.User) && !strings.Contains(req.User, "..")
	}
	if !joinHost.MatchString(req.Hostname) || (req.OS != "linux" && req.OS != "windows") || (req.Arch != "amd64" && req.Arch != "arm64") || !validUser {
		return JoinStarted{}, ErrJoinInput
	}
	var secret [32]byte
	var codeBytes [8]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return JoinStarted{}, err
	}
	if _, err := rand.Read(codeBytes[:]); err != nil {
		return JoinStarted{}, err
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	for i := range codeBytes {
		codeBytes[i] = alphabet[int(codeBytes[i])%len(alphabet)]
	}
	code := string(codeBytes[:4]) + "-" + string(codeBytes[4:])
	raw := base64.RawURLEncoding.EncodeToString(secret[:])
	hash := sha256.Sum256([]byte(raw))
	expires := now.Add(15 * time.Minute).Truncate(time.Second)
	err := s.store.StartJoin(store.JoinRequest{Code: code, Hostname: req.Hostname, OS: req.OS, Arch: req.Arch, User: req.User, ClientIP: ip, CreatedAt: now, ExpiresAt: expires}, hash[:])
	if err != nil {
		return JoinStarted{}, err
	}
	return JoinStarted{code, raw, expires, 5}, nil
}

// JoinDisplayName capitalises the first character of each dash-separated word,
// preserving all remaining characters (host-b becomes Host-B).
func JoinDisplayName(host string) string {
	parts := strings.Split(host, "-")
	for i, p := range parts {
		r := []rune(p)
		if len(r) > 0 {
			r[0] = unicode.ToUpper(r[0])
			parts[i] = string(r)
		}
	}
	return strings.Join(parts, "-")
}
func (s *Service) ListJoins() ([]store.JoinRequest, error) {
	j := s.joins()
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.prune(now)
	rows, err := s.store.ListJoins(now)
	if err != nil {
		return nil, err
	}
	for i := range rows {
		if rows[i].State == "approved" {
			if _, ok := j.payloads[rows[i].Code]; !ok {
				if err := s.store.TransitionJoin(rows[i].Code, "approved", "approval_expired", nil); err != nil {
					return nil, err
				}
				rows[i].State = "approval_expired"
			}
		}
	}
	return rows, nil
}
func (s *Service) DecideJoin(ctx context.Context, code, name string, approve bool, hub string, bundle JoinBundle, actor Actor, monitorOnly ...bool) error {
	j := s.joins()
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.prune(now)
	rows, err := s.store.ListJoins(now)
	if err != nil {
		return err
	}
	var request *store.JoinRequest
	for i := range rows {
		if rows[i].Code == code {
			request = &rows[i]
		}
	}
	if request == nil {
		return store.ErrJoinState
	}
	if approve && request.State == "approved" {
		if _, ok := j.payloads[code]; ok {
			return store.ErrJoinState
		}
	}
	from := request.State
	audit := auditFromActor(actor)
	audit.Subject = code
	audit.OK = true
	if !approve {
		audit.Action = store.AuditJoinReject
		if err := s.store.TransitionJoin(code, from, "rejected", &audit); err != nil {
			return err
		}
		delete(j.payloads, code)
		return nil
	}
	expectedBundle := hub + "/v1/join/bundle/" + request.OS + "-" + request.Arch
	legacyLinuxBundle := request.OS == "linux" && bundle.URL == hub+"/v1/join/bundle/"+request.Arch
	if bundle.SHA256 == "" || (bundle.URL != expectedBundle && !legacyLinuxBundle) {
		return errors.New("agent download unavailable")
	}
	monitor := len(monitorOnly) == 1 && monitorOnly[0]
	preview, err := s.PreviewEnrollToken(EnrollTokenPreviewRequest{MonitorOnly: monitor, DisplayName: name, TTLSeconds: 600})
	if err != nil {
		return err
	}
	var ts *JoinTailnet
	if request.OS == "linux" && j.keys.Configured() {
		key, err := j.keys.Mint(ctx, code)
		if err != nil {
			return err
		}
		ts = &JoinTailnet{key, []string{j.keys.Tag}, strings.ToLower(request.Hostname)}
	}
	key, err := NewIdempotencyKey("join")
	if err != nil {
		return err
	}
	ticket, err := s.CreateEnrollToken(EnrollTokenCreateRequest{MonitorOnly: monitor, DisplayName: name, TTLSeconds: 600, PreviewDigest: preview.PreviewDigest, Reason: "Approve waiting machine " + code, IdempotencyKey: key, Actor: actor})
	if err != nil {
		return err
	}
	audit.Action = store.AuditJoinApprove
	audit.MachineID = ticket.MachineID
	if err = s.store.TransitionJoin(code, from, "approved", &audit); err != nil {
		_, _ = s.store.RevokeEnrollToken(ticket.MachineID)
		return err
	}
	j.payloads[code] = joinDelivery{JoinPayload{monitor, "approved", ticket.DisplayName, ticket.EnrollmentToken, hub, ts, bundle}, now.Add(10 * time.Minute)}
	return nil
}
func (s *Service) PollJoin(secret string) (JoinPayload, int, error) {
	j := s.joins()
	j.mu.Lock()
	defer j.mu.Unlock()
	now := time.Now()
	j.prune(now)
	if len(secret) != 43 {
		return JoinPayload{}, 404, nil
	}
	hash := sha256.Sum256([]byte(secret))
	req, err := s.store.LookupJoin(hash[:], now)
	if errors.Is(err, store.ErrNotFound) {
		return JoinPayload{}, 404, nil
	}
	if err != nil {
		return JoinPayload{}, 500, err
	}
	if !now.Before(req.ExpiresAt) {
		delete(j.payloads, req.Code)
		return JoinPayload{State: "expired"}, 410, nil
	}
	switch req.State {
	case "pending":
		return JoinPayload{State: "pending"}, 202, nil
	case "approved":
		payload, ok := j.payloads[req.Code]
		if !ok {
			if err := s.store.TransitionJoin(req.Code, "approved", "approval_expired", nil); err != nil {
				return JoinPayload{}, 500, err
			}
			return JoinPayload{State: "approval_expired"}, 410, nil
		}
		if err := s.store.TransitionJoin(req.Code, "approved", "redeemed", nil); err != nil {
			return JoinPayload{}, 500, err
		}
		delete(j.payloads, req.Code)
		return payload.payload, 200, nil
	default:
		return JoinPayload{State: req.State}, 410, nil
	}
}

// Bundle access is separate from payload redemption so the first successful
// poll ends download authority. The script fetches while pending and verifies
// the archive against the approved digest before extraction.
func (s *Service) JoinBundleAuthorized(secret, os, arch string) bool {
	if len(secret) != 43 {
		return false
	}
	hash := sha256.Sum256([]byte(secret))
	now := time.Now()
	r, err := s.store.LookupJoin(hash[:], now)
	return err == nil && r.OS == os && r.Arch == arch && now.Before(r.ExpiresAt) && (r.State == "pending" || r.State == "approved")
}
