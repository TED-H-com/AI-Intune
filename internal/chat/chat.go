// Package chat adapts authenticated provider events to the Hub operator service.
package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/localauth"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/secrets"
	"github.com/teddashh/AI-Intune/internal/store"
)

type Config struct {
	ID              string `json:"id"`
	Kind            string `json:"kind"`
	Enabled         bool   `json:"enabled"`
	Destination     string `json:"destination"`
	SelfID          string `json:"self_id"`
	TokenRef        string `json:"token_ref"`
	SecretRef       string `json:"secret_ref"`
	PublicKeyRef    string `json:"public_key_ref"`
	ApprovalSeconds int    `json:"approval_seconds"`
}

func Load(path string) ([]Config, error) {
	if path == "" {
		return nil, nil
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("inbound config unavailable")
	}
	defer f.Close()
	var cs []Config
	d := json.NewDecoder(http.MaxBytesReader(nil, f, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&cs) != nil {
		return nil, errors.New("invalid inbound config")
	}
	if d.Decode(new(any)) != io.EOF {
		return nil, errors.New("invalid inbound config")
	}
	seen := map[string]bool{}
	for i := range cs {
		c := &cs[i]
		if seen[c.ID] || !regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`).MatchString(c.ID) || c.Destination == "" || c.SelfID == "" {
			return nil, errors.New("invalid inbound config")
		}
		seen[c.ID] = true
		if c.ApprovalSeconds == 0 {
			c.ApprovalSeconds = 600
		}
		if c.ApprovalSeconds < 1 || c.ApprovalSeconds > 600 {
			return nil, errors.New("invalid approval lifetime")
		}
		switch c.Kind {
		case "telegram":
			if channels.ValidateCredentialReference(c.SecretRef) != nil || channels.ValidateCredentialReference(c.TokenRef) != nil {
				return nil, errors.New("invalid inbound references")
			}
		case "discord":
			if channels.ValidateCredentialReference(c.PublicKeyRef) != nil {
				return nil, errors.New("invalid inbound references")
			}
		default:
			return nil, errors.New("invalid inbound kind")
		}
	}
	return cs, nil
}

type Engine struct {
	configs  map[string]Config
	store    *store.Store
	service  *operator.Service
	resolver secrets.SecretProvider
	mu       sync.Mutex
	rates    map[string]bucket
	now      func() time.Time
}
type bucket struct {
	start time.Time
	count int
}

func New(cs []Config, st *store.Store, svc *operator.Service, r secrets.SecretProvider) *Engine {
	e := &Engine{configs: map[string]Config{}, store: st, service: svc, resolver: r, rates: map[string]bucket{}, now: time.Now}
	for _, c := range cs {
		e.configs[c.ID] = c
	}
	return e
}

type Status struct {
	ID, Kind string
	Enabled  bool
}

func (e *Engine) Status() []Status {
	out := []Status{}
	for _, c := range e.configs {
		out = append(out, Status{c.ID, c.Kind, c.Enabled})
	}
	return out
}
func (e *Engine) secret(ctx context.Context, ref string) string {
	if e.resolver == nil {
		return ""
	}
	s, err := e.resolver.Get(ctx, ref)
	if err != nil {
		return ""
	}
	return s.Reveal()
}
func (e *Engine) rate(key string, limit int, now time.Time) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for k, v := range e.rates {
		if now.Sub(v.start) >= time.Minute {
			delete(e.rates, k)
		}
	}
	b := e.rates[key]
	if b.start.IsZero() {
		if len(e.rates) >= 4096 {
			return false
		}
		b.start = now
	}
	b.count++
	e.rates[key] = b
	return b.count <= limit
}
func (e *Engine) principal(channel, user string) (operatorauth.Principal, bool) {
	users, err := e.store.ChatUsers()
	if err != nil {
		return operatorauth.Principal{}, false
	}
	id := ""
	for _, u := range users {
		if u.ChannelID == channel && u.UserID == user {
			id = u.AccountID
			break
		}
	}
	if id == "" {
		return operatorauth.Principal{}, false
	}
	accounts, err := e.store.ListHubUsers()
	if err != nil {
		return operatorauth.Principal{}, false
	}
	for _, a := range accounts {
		if a.AccountID == id && !a.Disabled {
			p := localauth.AccountPrincipal(a, operatorauth.CapabilityNames{View: "local/cap/clawctl-view", Operate: "local/cap/clawctl-operate", Admin: "local/cap/clawctl-admin"})
			p.AuthMethod = operatorauth.AuthMethodChatAllowlist
			p.NodeStableID = "chat:" + channel + ":" + user
			p.DeviceName = "chat"
			return p, true
		}
	}
	return operatorauth.Principal{}, false
}
func chatActor(p operatorauth.Principal, permission operatorauth.Permission) operator.Actor {
	p.AuthorizedCapability = ""
	switch permission {
	case operatorauth.View:
		p.AuthorizedCapability = p.GrantedCapabilities.View
	case operatorauth.Admin:
		p.AuthorizedCapability = p.GrantedCapabilities.Admin
	}
	r := operatorauth.WithPrincipal(&http.Request{}, p)
	return operator.ActorFromRequest(r, "chat")
}
func (e *Engine) audit(channel, user, outcome string, p operatorauth.Principal) error {
	a := store.AuditEntry{Action: "chat-command", Subject: channel, Detail: outcome, WhoUser: user, SourceKind: "chat", OK: outcome == "command received" || outcome == "alert acknowledged"}
	if p.StableSubject() != "" {
		operator.ApplyActor(&a, chatActor(p, operatorauth.View))
	}
	return e.store.RecordAudit(a)
}

// Explicit forbidden domains remain denied even if the positive command set grows.
func Dangerous(command string) bool {
	for _, s := range []string{"delete", "retire", "mfa", "auth", "token", "secret", "password", "enroll", "terminal", "script"} {
		if strings.Contains(strings.ToLower(command), s) {
			return true
		}
	}
	return false
}

type event struct {
	id, user, destination, command, decision, approval string
	bot                                                bool
}
type reply struct{ text, approval string }

func (e *Engine) execute(ctx context.Context, c Config, v event) reply {
	now := e.now()
	if v.bot || v.user == c.SelfID {
		_ = e.audit(c.ID, v.user, "bot ignored", operatorauth.Principal{})
		return reply{}
	}
	if v.destination != c.Destination {
		_ = e.audit(c.ID, v.user, "destination ignored", operatorauth.Principal{})
		return reply{}
	}
	if !e.rate("c:"+c.ID, 60, now) || !e.rate("u:"+c.ID+":"+v.user, 10, now) {
		_ = e.audit(c.ID, v.user, "rate limited", operatorauth.Principal{})
		return reply{}
	}
	if v.id == "" || len(v.id) > 128 {
		return reply{}
	}
	fresh, err := e.store.ClaimChatEvent(ctx, c.ID, v.id, now)
	if err != nil || !fresh {
		return reply{}
	}
	p, ok := e.principal(c.ID, v.user)
	if !ok {
		_ = e.audit(c.ID, v.user, "unknown user ignored", p)
		return reply{}
	}
	if err = e.audit(c.ID, v.user, "command received", p); err != nil {
		return reply{}
	}
	fail := func(outcome string) reply { _ = e.audit(c.ID, v.user, outcome, p); return reply{text: outcome} }
	if v.approval != "" {
		if !p.Has(operatorauth.Admin) {
			return fail("permission denied")
		}
		a := store.AuditEntry{}
		operator.ApplyActor(&a, chatActor(p, operatorauth.Admin))
		approve := v.decision == "approve"
		ap, err := e.store.ConsumeChatApproval(ctx, v.approval, c.ID, v.destination, now, a, approve)
		if err != nil {
			return fail("approval unavailable or expired")
		}
		if !approve {
			return reply{text: "Denied"}
		}
		// Revalidate the requester's current mapping too; removal revokes outstanding intent.
		requester, ok := e.principal(c.ID, ap.Requester)
		if !ok || !requester.Has(operatorauth.Admin) {
			return fail("requester permission revoked")
		}
		var req store.DiskAlertAckRequest
		if json.Unmarshal([]byte(ap.Body), &req) != nil || req.ID != ap.Target {
			return fail("approval unavailable")
		}
		_, err = e.service.DiskAlertAcknowledge(req, true, ap.ID, chatActor(p, operatorauth.Admin))
		if err != nil {
			return fail("action failed")
		}
		return fail("alert acknowledged")
	}
	fields := strings.Fields(strings.TrimPrefix(v.command, "/"))
	if len(fields) == 0 {
		return reply{}
	}
	cmd := strings.Split(fields[0], "@")[0]
	if Dangerous(cmd) {
		return fail("action blocked")
	}
	permission := operatorauth.View
	if cmd == "ack-alert" {
		permission = operatorauth.Admin
	}
	if !p.Has(permission) {
		return fail("permission denied")
	}
	switch cmd {
	case "status", "machines":
		if len(fields) != 1 {
			return fail("invalid command")
		}
		r, err := e.service.ListMachinesPage(operator.MachineListRequest{Limit: 10}, now)
		if err != nil {
			return fail("query failed")
		}
		text := fmt.Sprintf("Machines: %d; reporting: %d", r.Total, r.Reporting)
		if cmd == "machines" {
			for _, m := range r.Items {
				text += "\n" + m.MachineID
			}
		}
		return reply{text: text}
	case "jobs":
		if len(fields) != 1 {
			return fail("invalid command")
		}
		r, err := e.service.ListJobs(operator.JobListRequest{Limit: 10}, now)
		if err != nil {
			return fail("query failed")
		}
		text := fmt.Sprintf("Jobs: %d", r.Total)
		for _, j := range r.Items {
			text += "\n" + j.JobID
		}
		return reply{text: text}
	case "alerts":
		if len(fields) != 1 {
			return fail("invalid command")
		}
		r, err := e.service.DiskAlertsList("")
		if err != nil {
			return fail("query failed")
		}
		if len(r) > 10 {
			r = r[:10]
		}
		text := "Recent disk alerts"
		for _, a := range r {
			text += "\n" + a.ID
		}
		return reply{text: text}
	case "ack-alert":
		if len(fields) != 2 || len(fields[1]) > 128 {
			return fail("usage: ack-alert ALERT_ID")
		}
		req := store.DiskAlertAckRequest{ID: fields[1], Reason: "Human approved chat acknowledgment"}
		preview, err := e.service.DiskAlertAcknowledge(req, false, "", chatActor(p, operatorauth.Admin))
		if err != nil {
			return fail("preview failed")
		}
		req.ExpiresAt = preview.ExpiresAt
		req.PreviewDigest = preview.PreviewDigest
		raw, _ := json.Marshal(req)
		id, err := operator.NewIdempotencyKey("chat")
		if err != nil {
			return fail("approval unavailable")
		}
		ttl := c.ApprovalSeconds
		if ttl <= 0 {
			ttl = 600
		}
		a := store.AuditEntry{}
		operator.ApplyActor(&a, chatActor(p, operatorauth.Admin))
		ap := store.ChatApproval{ID: id, ChannelID: c.ID, Destination: v.destination, Requester: v.user, Target: req.ID, Body: string(raw), Expires: now.Add(time.Duration(ttl) * time.Second).Unix()}
		if e.store.CreateChatApproval(ctx, ap, a) != nil {
			return fail("approval unavailable")
		}
		return reply{text: "Approve acknowledgment of alert " + req.ID + "? Expires " + time.Unix(ap.Expires, 0).UTC().Format(time.RFC3339), approval: id}
	default:
		return fail("unsupported command")
	}
}
