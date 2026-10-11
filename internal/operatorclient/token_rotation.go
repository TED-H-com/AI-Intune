package operatorclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	return c.rotateTokenFileWithOps(ctx, path, minRemaining, force, defaultTokenFileOps())
}
func (c *Client) rotateTokenFileWithOps(ctx context.Context, path string, minRemaining time.Duration, force bool, ops tokenFileOps) (bool, error) {
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
	if err = replaceServiceTokenFileWithOps(path, current, result.Token, ops); err != nil {
		return false, err
	}
	c.token = result.Token
	if _, err = c.ServiceTokenSelf(ctx); err != nil {
		return false, fmt.Errorf("new token saved at %q; authentication confirmation failed; retry using that file", path)
	}
	return true, nil
}

type tokenFileOps struct {
	rename   func(string, string) error
	syncFile func(*os.File) error
	syncDir  func(*os.File) error
}

func defaultTokenFileOps() tokenFileOps {
	return tokenFileOps{os.Rename, (*os.File).Sync, (*os.File).Sync}
}
func replaceServiceTokenFile(path, current, next string) error {
	return replaceServiceTokenFileWithOps(path, current, next, defaultTokenFileOps())
}
func replaceServiceTokenFileWithOps(path, current, next string, ops tokenFileOps) error {
	if !store.ValidServiceSecret(next) {
		return errors.New("invalid replacement token")
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".service-token-*")
	if err != nil {
		return errors.New("cannot create temporary token file; retry rotation during overlap")
	}
	name := f.Name()
	keep := false
	defer func() {
		f.Close()
		if !keep {
			os.Remove(name)
		}
	}()
	if err = f.Chmod(0600); err != nil {
		return errors.New("cannot secure temporary token file; retry rotation during overlap")
	}
	if _, err = f.WriteString(next + "\n"); err != nil {
		return errors.New("cannot write temporary token file; retry rotation during overlap")
	}
	keep = true
	recovery := func(reason string) error {
		return fmt.Errorf("%s; recovery token file: %q (0600); install it before the overlap ends", reason, name)
	}
	if err = ops.syncFile(f); err != nil {
		return recovery("cannot sync temporary token file")
	}
	if err = f.Close(); err != nil {
		return recovery("cannot close temporary token file")
	}
	actual, err := ReadServiceTokenFile(path)
	if err != nil || actual != current {
		return recovery("token file changed or is unsafe")
	}
	if err = ops.rename(name, path); err != nil {
		return recovery("cannot replace token file")
	}
	// The durable credential now lives at the destination. Never authenticate it
	// until rename and directory fsync complete, so pre-install failures allow re-issue.
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("new token saved at %q; cannot open token directory", path)
	}
	defer d.Close()
	if err = ops.syncDir(d); err != nil {
		return fmt.Errorf("new token saved at %q; cannot sync token directory; retry directory fsync before confirming authentication", path)
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
