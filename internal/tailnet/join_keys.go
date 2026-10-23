package tailnet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// JoinKeys holds credentials only in process memory. BaseURL is injectable for
// tests; deployment configuration must use the production Tailscale authority.
type JoinKeys struct {
	ClientID, ClientSecret, Tag, BaseURL string
	HTTP                                 *http.Client
}

var joinTag = regexp.MustCompile(`^tag:[a-z0-9-]{1,63}$`)

func (c *JoinKeys) Validate() error {
	if c.Tag == "" {
		c.Tag = "tag:fleet"
	}
	if !joinTag.MatchString(c.Tag) {
		return errors.New("invalid Tailscale join tag")
	}
	if (c.ClientID == "") != (c.ClientSecret == "") {
		return errors.New("both Tailscale OAuth credentials are required")
	}
	return nil
}
func (c *JoinKeys) Configured() bool { return c != nil && c.ClientID != "" && c.ClientSecret != "" }
func (c *JoinKeys) Mint(ctx context.Context, code string) (string, error) {
	if err := c.Validate(); err != nil {
		return "", err
	}
	base := c.BaseURL
	if base == "" {
		base = "https://api.tailscale.com"
	}
	client := &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if c.HTTP != nil {
		copy := *c.HTTP
		copy.CheckRedirect = client.CheckRedirect
		copy.Timeout = 15 * time.Second
		client = &copy
	}
	call := func(path, kind, body, token string, out any) error {
		req, err := http.NewRequestWithContext(ctx, "POST", strings.TrimRight(base, "/")+path, strings.NewReader(body))
		if err != nil {
			return errors.New("Tailscale request unavailable")
		}
		req.Header.Set("Content-Type", kind)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		res, err := client.Do(req)
		if err != nil {
			return errors.New("Tailscale request failed")
		}
		defer res.Body.Close()
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			return errors.New("Tailscale rejected key request")
		}
		data, err := io.ReadAll(io.LimitReader(res.Body, 16385))
		if err != nil || len(data) > 16384 {
			return errors.New("Tailscale response unavailable")
		}
		if json.Unmarshal(data, out) != nil {
			return errors.New("Tailscale response invalid")
		}
		return nil
	}
	var token struct {
		AccessToken string `json:"access_token"`
	}
	form := url.Values{"grant_type": {"client_credentials"}, "client_id": {c.ClientID}, "client_secret": {c.ClientSecret}}
	if err := call("/api/v2/oauth/token", "application/x-www-form-urlencoded", form.Encode(), "", &token); err != nil {
		return "", err
	}
	if token.AccessToken == "" {
		return "", errors.New("Tailscale access token unavailable")
	}
	body, _ := json.Marshal(map[string]any{"capabilities": map[string]any{"devices": map[string]any{"create": map[string]any{"reusable": false, "ephemeral": false, "preauthorized": true, "tags": []string{c.Tag}}}}, "expirySeconds": 600, "description": "clawctl join " + code})
	var key struct {
		Key string `json:"key"`
	}
	if err := call("/api/v2/tailnet/-/keys", "application/json", string(body), token.AccessToken, &key); err != nil {
		return "", err
	}
	if key.Key == "" || len(key.Key) > 4096 || strings.ContainsAny(key.Key, "\r\n") {
		return "", errors.New("Tailscale key unavailable")
	}
	return key.Key, nil
}
