// Package secrets resolves references without exposing values in diagnostic output.
package secrets

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Secret struct{ value string }

func NewSecret(value string) Secret { return Secret{value: value} }

// Reveal explicitly crosses the boundary into a secret-consuming integration.
func (s Secret) Reveal() string              { return s.value }
func (Secret) String() string                { return "[REDACTED]" }
func (Secret) GoString() string              { return "[REDACTED]" }
func (Secret) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, "[REDACTED]") }
func (Secret) MarshalJSON() ([]byte, error)  { return []byte(`"[REDACTED]"`), nil }

var ErrMissing = errors.New("secret missing")
var ErrNotConfigured = errors.New("secret provider not configured")

type Reference struct {
	Name string `json:"name"`
	Ref  string `json:"ref"`
}

// SecretProvider resolves values independently of delivery transport. Pull
// consumers use a locally scoped registry; brokered delivery requires a future
// authorized transport and does not change reference URIs.
type SecretProvider interface {
	Get(context.Context, string) (Secret, error)
	List(context.Context, string) ([]Reference, error)
	Health(context.Context) error
}

// Registry is configured at startup. List enumerates configured references only,
// never an entire process environment or arbitrary filesystem.
type Registry struct {
	providers  map[string]SecretProvider
	references []Reference
}

func New(refs []Reference) *Registry {
	r := &Registry{providers: make(map[string]SecretProvider), references: append([]Reference(nil), refs...)}
	r.Register("env", localProvider{scheme: "env"})
	r.Register("file", localProvider{scheme: "file"})
	r.Register("bws", unconfigured{})
	return r
}
func (r *Registry) Register(scheme string, p SecretProvider) { r.providers[scheme] = p }
func (r *Registry) Get(ctx context.Context, ref string) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	u, err := url.Parse(ref)
	if err != nil {
		return Secret{}, errors.New("invalid secret reference")
	}
	p, ok := r.providers[u.Scheme]
	if !ok {
		return Secret{}, errors.New("unknown secret provider")
	}
	return p.Get(ctx, ref)
}
func (r *Registry) List(ctx context.Context, scope string) ([]Reference, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := []Reference{}
	for _, ref := range r.references {
		if scope == "" || strings.HasPrefix(ref.Ref, scope) {
			out = append(out, ref)
		}
	}
	return out, nil
}
func (r *Registry) Health(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	keys := []string{}
	for k := range r.providers {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if err := r.providers[k].Health(ctx); err != nil {
			if errors.Is(err, ErrNotConfigured) {
				return fmt.Errorf("%s: %w", k, ErrNotConfigured)
			}
			return fmt.Errorf("%s: provider unavailable", k)
		}
	}
	return nil
}

type localProvider struct {
	scheme   string
	snapshot map[string]string
	path     string
}

func (p localProvider) Health(ctx context.Context) error { return ctx.Err() }
func (p localProvider) List(ctx context.Context, scope string) ([]Reference, error) {
	return []Reference{}, ctx.Err()
}
func (p localProvider) Get(ctx context.Context, ref string) (Secret, error) {
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	u, err := url.Parse(ref)
	if err != nil || u.Scheme != p.scheme || u.User != nil || u.RawQuery != "" {
		return Secret{}, errors.New("invalid secret reference")
	}
	var value string
	var ok bool
	switch p.scheme {
	case "env":
		if u.Host == "" || u.Path != "" || u.Fragment != "" {
			return Secret{}, errors.New("invalid env reference")
		}
		value, ok = os.LookupEnv(u.Host)
	case "file":
		if u.Host != "" || !filepath.IsAbs(u.Path) || u.Fragment == "" {
			return Secret{}, errors.New("invalid file reference")
		}
		values := p.snapshot
		if values == nil {
			var err error
			values, _, err = ReadEnvFile(u.Path)
			if err != nil {
				return Secret{}, err
			}
		} else if u.Path != p.path {
			return Secret{}, errors.New("invalid snapshot reference")
		}

		value, ok = values[u.Fragment]
	}
	if !ok || value == "" {
		return Secret{}, ErrMissing
	}
	return NewSecret(value), nil
}

type unconfigured struct{}

func (unconfigured) Get(context.Context, string) (Secret, error)       { return Secret{}, ErrNotConfigured }
func (unconfigured) List(context.Context, string) ([]Reference, error) { return nil, ErrNotConfigured }
func (unconfigured) Health(context.Context) error                      { return ErrNotConfigured }
func FileReference(path, key string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	return (&url.URL{Scheme: "file", Path: absolute, Fragment: key}).String()
}

var NotifyKeys = []string{"TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "CLAWCTL_NOTIFY_WEBHOOK_URL", "CLAWCTL_NOTIFY_WEBHOOK_SECRET"}

func NotifyReferences(path string) []Reference {
	out := []Reference{}
	if strings.TrimSpace(path) != "" {
		for _, k := range NotifyKeys {
			out = append(out, Reference{Name: k, Ref: FileReference(path, k)})
		}
	}
	return out
}

// ReadEnvFile preserves the legacy notify parser and one MiB read limit.
func ReadEnvFile(path string) (map[string]string, os.FileMode, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, errors.New("secret file cannot read")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, 0, errors.New("secret file cannot read")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil, 0, errors.New("secret file cannot read")
	}
	return ParseEnv(raw), info.Mode().Perm(), nil
}

func ParseEnv(raw []byte) map[string]string {
	text := string(raw)
	text = strings.TrimPrefix(text, "\ufeff")
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\r", "\n")
	out := make(map[string]string)
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		out[key] = val
	}
	return out
}

// NewFileSnapshot resolves all keys from one read so a concurrent rotation
// cannot mix credentials from different file versions. Call again per delivery.
func NewFileSnapshot(path string) (*Registry, os.FileMode, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, 0, errors.New("invalid secret file path")
	}
	values, mode, err := ReadEnvFile(absolute)
	if err != nil {
		return nil, 0, err
	}
	r := New(NotifyReferences(absolute))
	r.Register("file", localProvider{scheme: "file", snapshot: values, path: absolute})
	return r, mode, nil
}
