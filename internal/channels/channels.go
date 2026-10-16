// Package channels implements outbound delivery using reference-only credentials.
package channels

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

const (
	telegramMaxRunes       = 3900
	telegramTruncateSuffix = "\n… (truncated; full text is on the Hub)"
	notifyRequestTimeout   = 20 * time.Second
	notifyResponseLimit    = 1 << 20
)

func newNotifyHTTPClient() *http.Client {
	return &http.Client{Timeout: notifyRequestTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

type Message struct{ Kind, Text string }
type HealthStatus string

const (
	Ready       HealthStatus = "ready"
	Unavailable HealthStatus = "unavailable"
)

type Provider interface {
	Name() string
	Kind() string
	Send(context.Context, Message) error
	Health(context.Context) (HealthStatus, error)
}

// InboundHandler is retained for transport compatibility. Provider-authenticated
// inbound HTTP commands live in internal/chat, which adapts to the operator API.
// Dangerous actions are unavailable there; supported mutations require approval.
type InboundHandler interface {
	HandleInbound(context.Context, Message) error
}

// Config contains references only. Never place credential values in these fields.
type Config struct {
	ID        string
	Kind      string
	TokenRef  string
	ChatRef   string
	URLRef    string
	SecretRef string
}
type outbound struct {
	config   Config
	resolver secrets.SecretProvider
	apiBase  string
}

// Telegram delivers messages using Telegram's Bot API.
type Telegram struct{ *outbound }

// Webhook delivers signed JSON notifications.
type Webhook struct{ *outbound }

func NewTelegram(c Config, r secrets.SecretProvider) *Telegram {
	c.Kind = "telegram"
	return &Telegram{&outbound{config: c, resolver: r, apiBase: "https://api.telegram.org"}}
}
func NewWebhook(c Config, r secrets.SecretProvider) *Webhook {
	c.Kind = "webhook"
	return &Webhook{&outbound{config: c, resolver: r}}
}
func New(c Config, r secrets.SecretProvider) Provider {
	switch c.Kind {
	case "discord":
		return NewDiscord(c, r)
	case "telegram":
		return NewTelegram(c, r)
	case "webhook":
		return NewWebhook(c, r)
	default:
		return &outbound{config: c, resolver: r}
	}
}

// NewTelegramForAPI allows an alternate API endpoint for transport tests.
func NewTelegramForAPI(c Config, r secrets.SecretProvider, base string) Provider {
	p := NewTelegram(c, r)
	p.apiBase = base
	return p
}
func (p *outbound) String() string               { return "channel provider" }
func (p *outbound) GoString() string             { return p.String() }
func (p *outbound) MarshalJSON() ([]byte, error) { return []byte(`"channel provider"`), nil }
func (p *outbound) Name() string                 { return p.config.ID }
func (p *outbound) Kind() string                 { return p.config.Kind }

type credentials struct{ token, chatID, webhookURL, webhookSecret string }

func (c credentials) secrets() []string {
	return []string{c.token, c.chatID, c.webhookURL, c.webhookSecret}
}
func (p *outbound) credentials(ctx context.Context) (credentials, error) {
	var c credentials
	if e := ValidateConfig(p.config); e != nil {
		return c, e
	}
	if p.resolver == nil {
		return c, errors.New("channel credentials unavailable")
	}
	refs := []string{}
	dst := []*string{}
	switch p.Kind() {
	case "telegram":
		refs = []string{p.config.TokenRef, p.config.ChatRef}
		dst = []*string{&c.token, &c.chatID}
	case "discord":
		if p.config.URLRef != "" {
			refs = []string{p.config.URLRef}
			dst = []*string{&c.webhookURL}
		} else {
			refs = []string{p.config.TokenRef, p.config.ChatRef}
			dst = []*string{&c.token, &c.chatID}
		}
	case "webhook":
		refs = []string{p.config.URLRef}
		dst = []*string{&c.webhookURL}
	default:
		return c, errors.New("unsupported channel kind")
	}
	for i, ref := range refs {
		v, e := p.resolver.Get(ctx, ref)
		if e != nil || strings.TrimSpace(v.Reveal()) == "" {
			return credentials{}, errors.New("channel credentials unavailable")
		}
		*dst[i] = strings.TrimSpace(v.Reveal())
	}
	if p.Kind() == "webhook" && p.config.SecretRef != "" {
		v, e := p.resolver.Get(ctx, p.config.SecretRef)
		if e != nil {
			return credentials{}, errors.New("channel credentials unavailable")
		}
		c.webhookSecret = strings.TrimSpace(v.Reveal())
	}
	if p.Kind() == "webhook" || c.webhookURL != "" {
		if e := ValidateWebhookURL(c.webhookURL); e != nil {
			return credentials{}, e
		}
	}
	return c, nil
}
func (p *outbound) Health(ctx context.Context) (HealthStatus, error) {
	_, e := p.credentials(ctx)
	if e != nil {
		return Unavailable, e
	}
	return Ready, nil
}
func (p *outbound) Send(ctx context.Context, m Message) error {
	c, e := p.credentials(ctx)
	if e != nil {
		return e
	}
	if strings.TrimSpace(m.Text) == "" {
		return errors.New("empty notification body")
	}
	if p.Kind() == "webhook" {
		return sendWebhook(ctx, c, m.Kind, m.Text)
	}
	form := url.Values{"chat_id": {c.chatID}, "text": {truncateTelegram(m.Text)}, "disable_web_page_preview": {"true"}}
	_, desc, e := telegramAPI(ctx, p.apiBase, c.token, "sendMessage", form, c.secrets())
	if e != nil {
		return sanitizeNotifyError(e, c.secrets())
	}
	if desc != "" {
		return sanitizeNotifyError(errors.New(desc), c.secrets())
	}
	return nil
}
func truncateTelegram(body string) string {
	if utf8.RuneCountInString(body) <= telegramMaxRunes {
		return body
	}
	runes := []rune(body)
	return string(runes[:telegramMaxRunes]) + telegramTruncateSuffix
}

type telegramAPIResponse struct {
	OK          bool            `json:"ok"`
	Description string          `json:"description"`
	Result      json.RawMessage `json:"result"`
}

func telegramAPI(ctx context.Context, apiBase, token, method string, form url.Values, secrets []string) (telegramAPIResponse, string, error) {
	var parsed telegramAPIResponse
	endpoint := strings.TrimRight(apiBase, "/") + "/bot" + token + "/" + method
	reqCtx, cancel := context.WithTimeout(ctx, notifyRequestTimeout)
	defer cancel()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, endpoint, body)
	if err != nil {
		return parsed, "", sanitizeNotifyError(err, secrets)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.Header.Set("User-Agent", "clawctl-hub")
	resp, err := newNotifyHTTPClient().Do(req)
	if err != nil {
		return parsed, "", sanitizeNotifyError(err, secrets)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, notifyResponseLimit))
	_ = json.Unmarshal(raw, &parsed)
	if resp.StatusCode == http.StatusOK && parsed.OK {
		return parsed, "", nil
	}
	if parsed.Description != "" {
		return parsed, parsed.Description, nil
	}
	if resp.StatusCode != http.StatusOK {
		return parsed, "", fmt.Errorf("Telegram HTTP %d", resp.StatusCode)
	}
	return parsed, "", errors.New("Telegram request failed")
}

type webhookPayload struct {
	Kind   string `json:"kind"`
	Text   string `json:"text"`
	SentAt string `json:"sent_at"`
}

func sendWebhook(ctx context.Context, cfg credentials, kind, body string) error {
	payload, err := json.Marshal(webhookPayload{
		Kind:   kind,
		Text:   body,
		SentAt: time.Now().UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	reqCtx, cancel := context.WithTimeout(ctx, notifyRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, cfg.webhookURL, bytes.NewReader(payload))
	if err != nil {
		return sanitizeNotifyError(err, cfg.secrets())
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clawctl-hub")
	if cfg.webhookSecret != "" {
		mac := hmac.New(sha256.New, []byte(cfg.webhookSecret))
		_, _ = mac.Write(payload)
		req.Header.Set("X-Clawctl-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}
	resp, err := newNotifyHTTPClient().Do(req)
	if err != nil {
		return sanitizeNotifyError(err, cfg.secrets())
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, notifyResponseLimit))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return nil
}

// sanitizeNotifyError unwraps *url.Error (which embeds the full URL, often
// including a bot token or webhook secret) down to the operation and inner
// error, then strips any remaining secret substrings.
func sanitizeNotifyError(err error, secrets []string) error {
	if err == nil {
		return nil
	}
	var uerr *url.Error
	if errors.As(err, &uerr) {
		if uerr.Err != nil {
			err = fmt.Errorf("%s: %v", uerr.Op, uerr.Err)
		} else {
			err = errors.New(uerr.Op)
		}
	}
	msg := err.Error()
	redacted := msg
	for _, s := range secrets {
		if s == "" {
			continue
		}
		redacted = strings.ReplaceAll(redacted, s, "[redacted]")
	}
	if redacted == msg {
		return err
	}
	return errors.New(redacted)
}

// ValidateConfig rejects raw credential fields. References are never rendered by
// the Channels UI; reference paths may themselves contain sensitive identifiers.
func ValidateConfig(c Config) error {
	refs := []string{}
	switch c.Kind {
	case "discord":
		if c.SecretRef != "" || (c.URLRef != "" && (c.TokenRef != "" || c.ChatRef != "")) {
			return errors.New("unexpected credential reference")
		}
		if c.URLRef != "" {
			refs = []string{c.URLRef}
		} else {
			refs = []string{c.TokenRef, c.ChatRef}
		}
	case "telegram":
		refs = []string{c.TokenRef, c.ChatRef}
	case "webhook":
		refs = []string{c.URLRef}
		if c.SecretRef != "" {
			refs = append(refs, c.SecretRef)
		}
	default:
		return errors.New("unsupported channel kind")
	}
	for _, ref := range refs {
		if e := ValidateCredentialReference(ref); e != nil {
			return e
		}
	}
	if c.Kind == "telegram" && (c.URLRef != "" || c.SecretRef != "") || c.Kind == "webhook" && (c.TokenRef != "" || c.ChatRef != "") {
		return errors.New("unexpected credential reference")
	}
	return nil
}

// ValidateCredentialReference rejects raw values before configuration is persisted.
func ValidateCredentialReference(ref string) error {
	u, e := url.Parse(ref)
	if e != nil || u.User != nil || u.RawQuery != "" {
		return errors.New("credential reference required")
	}
	switch u.Scheme {
	case "env":
		if u.Host == "" || u.Path != "" || u.Fragment != "" {
			return errors.New("credential reference required")
		}
	case "file":
		if u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.Fragment == "" {
			return errors.New("credential reference required")
		}
	case "bws":
		if u.Host == "" {
			return errors.New("credential reference required")
		}
	default:
		return errors.New("credential reference required")
	}
	return nil
}

var webhookHTTPAllowedNet = netip.MustParsePrefix("100.64.0.0/10")

func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return errors.New("must be an absolute https URL (http is allowed only for loopback or 100.64.0.0/10)")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		addr, err := netip.ParseAddr(u.Hostname())
		if err != nil {
			return errors.New("must be an absolute https URL (http is allowed only for loopback or 100.64.0.0/10)")
		}
		addr = addr.Unmap()
		if addr.IsLoopback() || webhookHTTPAllowedNet.Contains(addr) {
			return nil
		}
		return errors.New("must be an absolute https URL (http is allowed only for loopback or 100.64.0.0/10)")
	default:
		return errors.New("must be an absolute https URL (http is allowed only for loopback or 100.64.0.0/10)")
	}
}

// NotifyConfigs adapts the existing notification env file without retaining
// resolved values. It is used only to seed the Channels management inventory.
func NotifyConfigs(path string) []Config {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	r, _, e := secrets.NewFileSnapshot(path)
	if e != nil {
		return nil
	}
	configs := []Config{
		{ID: "telegram", Kind: "telegram", TokenRef: secrets.FileReference(path, "TELEGRAM_BOT_TOKEN"), ChatRef: secrets.FileReference(path, "TELEGRAM_CHAT_ID")},
		{ID: "webhook", Kind: "webhook", URLRef: secrets.FileReference(path, "CLAWCTL_NOTIFY_WEBHOOK_URL"), SecretRef: secrets.FileReference(path, "CLAWCTL_NOTIFY_WEBHOOK_SECRET")},
	}
	out := []Config{}
	for _, c := range configs {
		if c.Kind == "webhook" {
			if value, e := r.Get(context.Background(), c.SecretRef); e != nil || strings.TrimSpace(value.Reveal()) == "" {
				c.SecretRef = ""
			}
		}
		if status, _ := New(c, r).Health(context.Background()); status == Ready {
			out = append(out, c)
		}
	}
	return out
}
