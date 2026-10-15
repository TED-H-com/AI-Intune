package channels

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

// Discord implements outbound REST delivery only; it never opens a gateway.
type Discord struct{ *outbound }

func NewDiscord(c Config, r secrets.SecretProvider) *Discord {
	c.Kind = "discord"
	return &Discord{&outbound{config: c, resolver: r, apiBase: "https://discord.com/api/v10"}}
}
func NewDiscordForAPI(c Config, r secrets.SecretProvider, base string) *Discord {
	p := NewDiscord(c, r)
	p.apiBase = base
	return p
}
func (p *Discord) Health(ctx context.Context) (HealthStatus, error) {
	c, e := p.credentials(ctx)
	if e != nil {
		return Unavailable, e
	}
	endpoint := c.webhookURL
	if endpoint == "" {
		endpoint = strings.TrimRight(p.apiBase, "/") + "/users/@me"
	}
	if e = p.request(ctx, c, http.MethodGet, endpoint, nil); e != nil {
		return Unavailable, e
	}
	return Ready, nil
}
func (p *Discord) Send(ctx context.Context, m Message) error {
	c, e := p.credentials(ctx)
	if e != nil {
		return e
	}
	if strings.TrimSpace(m.Text) == "" {
		return errors.New("empty notification body")
	}
	if len([]rune(m.Text)) > 2000 {
		return errors.New("Discord content exceeds 2000 characters")
	}
	endpoint := c.webhookURL
	if endpoint == "" {
		// A resolved destination must be a channel ID, never a path.
		if c.chatID == "" || strings.IndexFunc(c.chatID, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return errors.New("invalid Discord channel ID")
		}
		endpoint = strings.TrimRight(p.apiBase, "/") + "/channels/" + url.PathEscape(c.chatID) + "/messages"
	}
	body, _ := json.Marshal(struct {
		Content         string `json:"content"`
		AllowedMentions struct {
			Parse []string `json:"parse"`
		} `json:"allowed_mentions"`
	}{Content: m.Text, AllowedMentions: struct {
		Parse []string `json:"parse"`
	}{Parse: []string{}}})
	return p.request(ctx, c, http.MethodPost, endpoint, body)
}

const discordRetries = 2
const discordMaxWait = 5 * time.Second

func discordRetryDelay(header string, raw []byte) time.Duration {
	seconds, e := strconv.ParseFloat(header, 64)
	if e != nil {
		if date, err := http.ParseTime(header); err == nil {
			seconds = time.Until(date).Seconds()
		} else {
			var v struct {
				RetryAfter float64 `json:"retry_after"`
			}
			_ = json.Unmarshal(raw, &v)
			seconds = v.RetryAfter
		}
	}
	if math.IsNaN(seconds) || seconds <= 0 {
		return 0
	}
	if math.IsInf(seconds, 1) || seconds >= discordMaxWait.Seconds() {
		return discordMaxWait
	}
	return time.Duration(seconds * float64(time.Second))
}
func (p *Discord) request(ctx context.Context, c credentials, method, endpoint string, body []byte) error {
	for attempt := 0; attempt <= discordRetries; attempt++ {
		reqCtx, cancel := context.WithTimeout(ctx, notifyRequestTimeout)
		req, e := http.NewRequestWithContext(reqCtx, method, endpoint, bytes.NewReader(body))
		if e != nil {
			cancel()
			return errors.New("Discord request failed")
		}
		req.Header.Set("User-Agent", "clawctl-hub")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bot "+c.token)
		}
		resp, e := newNotifyHTTPClient().Do(req)
		if e != nil {
			cancel()
			return errors.New("Discord request failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(resp.Body, notifyResponseLimit))
		resp.Body.Close()
		cancel()
		if readErr != nil {
			return errors.New("Discord response unavailable")
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			return nil
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			return fmt.Errorf("Discord HTTP %d", resp.StatusCode)
		}
		if attempt == discordRetries {
			return errors.New("Discord rate limit retry exhausted")
		}
		timer := time.NewTimer(discordRetryDelay(resp.Header.Get("Retry-After"), raw))
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.New("Discord request canceled")
		case <-timer.C:
		}
	}
	return errors.New("Discord request failed")
}
