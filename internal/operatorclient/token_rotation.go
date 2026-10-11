package operatorclient

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

type ServiceTokenSelf struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Scope     string     `json:"scope"`
	ExpiresAt time.Time  `json:"expires_at"`
	MaxExpiry *time.Time `json:"max_expiry"`
}

func (c *Client) ServiceTokenSelf(ctx context.Context) (ServiceTokenSelf, error) {
	var result ServiceTokenSelf
	req, err := c.newOperatorRequest(ctx, "GET", "/v1/operator/service-tokens/self", nil)
	if err != nil {
		return result, err
	}
	raw, err := c.doRaw(req)
	if err != nil {
		return result, err
	}
	if err = json.Unmarshal(raw.body, &result); err != nil || result.ID == "" || result.ExpiresAt.IsZero() {
		return result, errors.New("invalid service token metadata")
	}
	return result, nil
}

// RotateTokenFile never includes a plaintext credential in output or errors.
func (c *Client) RotateTokenFile(ctx context.Context, path string, minRemaining time.Duration, force bool) (bool, error) {
	if minRemaining < 0 {
		return false, errors.New("min-remaining must not be negative")
	}
	current, err := ReadServiceTokenFile(path)
	if err != nil {
		return false, err
	}
	if current != c.token {
		return false, errors.New("token file changed; retry")
	}
	self, err := c.ServiceTokenSelf(ctx)
	if err != nil {
		return false, err
	}
	if !force && time.Until(self.ExpiresAt) >= minRemaining {
		return false, nil
	}
	req, err := c.newOperatorRequest(ctx, "POST", "/v1/operator/service-tokens/rotate", strings.NewReader("{}"))
	if err != nil {
		return false, err
	}
	req.Header.Set("Content-Type", "application/json")
	raw, err := c.doRaw(req)
	if err != nil {
		return false, err
	}
	var result struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(raw.body, &result) != nil || !store.ValidServiceSecret(result.Token) {
		return false, errors.New("invalid rotation response")
	}
	if err = replaceServiceTokenFile(path, current, result.Token); err != nil {
		return false, err
	}
	c.token = result.Token
	return true, nil
}

func replaceServiceTokenFile(path, current, next string) error {
	if !store.ValidServiceSecret(next) {
		return errors.New("invalid replacement token")
	}
	actual, err := ReadServiceTokenFile(path)
	if err != nil {
		return err
	}
	if actual != current {
		return errors.New("token file changed; retry")
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".service-token-*")
	if err != nil {
		return errors.New("cannot create temporary token file")
	}
	name := f.Name()
	defer os.Remove(name)
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return errors.New("cannot secure temporary token file")
	}
	if _, err = f.WriteString(next + "\n"); err != nil {
		return errors.New("cannot write temporary token file")
	}
	if err = f.Sync(); err != nil {
		return errors.New("cannot sync temporary token file")
	}
	if err = f.Close(); err != nil {
		return errors.New("cannot close temporary token file")
	}
	actual, err = ReadServiceTokenFile(path)
	if err != nil || actual != current {
		return errors.New("token file changed; retry")
	}
	if err = os.Rename(name, path); err != nil {
		return errors.New("cannot replace token file")
	}
	d, err := os.Open(dir)
	if err != nil {
		return errors.New("cannot open token directory")
	}
	defer d.Close()
	if err = d.Sync(); err != nil {
		return errors.New("cannot sync token directory")
	}
	return nil
}

func ParseRotationDuration(raw string) (time.Duration, error) {
	if strings.HasSuffix(raw, "d") {
		n, err := time.ParseDuration(strings.TrimSuffix(raw, "d") + "h")
		if err != nil || n < 0 || n > time.Duration(1<<63-1)/24 {
			return 0, errors.New("invalid day duration")
		}
		return n * 24, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil || d < 0 {
		return 0, errors.New("invalid duration")
	}
	return d, nil
}
