package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var ErrDenied = errors.New("secret project denied")

// BWSConfig contains references and metadata only. Durations are seconds in JSON.
type BWSConfig struct {
	Binary         string   `json:"binary"`
	ServerURL      string   `json:"server_url"`
	TokenRef       string   `json:"token_ref"`
	TimeoutSeconds int      `json:"timeout_seconds"`
	TTLSeconds     int      `json:"ttl_seconds"`
	CacheDir       string   `json:"cache_dir"`
	DenyProjects   []string `json:"deny_projects"`
}
type BackendStatus struct {
	Configured     bool   `json:"configured"`
	Reachable      bool   `json:"reachable"`
	LastErrorClass string `json:"last_error_class,omitempty"`
}
type bwsEntry struct {
	Value       string    `json:"value"`
	ProjectID   string    `json:"project_id"`
	ProjectName string    `json:"project_name"`
	At          time.Time `json:"at"`
}
type bwsProject struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// BWS serializes refreshes, retaining only explicitly requested values.
type BWS struct {
	mu         sync.Mutex
	config     BWSConfig
	local      *Registry
	values     map[string]bwsEntry
	projects   []bwsProject
	projectsAt time.Time
	status     BackendStatus
}

// Formatting a provider must not expose its in-memory last-known-good values.
func (*BWS) String() string                { return "[REDACTED]" }
func (*BWS) GoString() string              { return "[REDACTED]" }
func (*BWS) Format(f fmt.State, verb rune) { _, _ = io.WriteString(f, "[REDACTED]") }

var projectID = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func NewBWS(c BWSConfig) (*BWS, error) {
	u, e := url.Parse(c.TokenRef)
	if e != nil || (u.Scheme != "env" && u.Scheme != "file") {
		return nil, errors.New("bws token must use env or file reference")
	}
	if c.ServerURL == "" {
		c.ServerURL = "https://vault.bitwarden.com"
	}
	u, e = url.Parse(c.ServerURL)
	if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("invalid bws server URL")
	}
	if c.Binary == "" {
		c.Binary = "bws"
	}
	if c.TimeoutSeconds < 0 || c.TTLSeconds < 0 {
		return nil, errors.New("invalid bws duration")
	}
	if c.TimeoutSeconds == 0 {
		c.TimeoutSeconds = 10
	}
	if c.TTLSeconds == 0 {
		c.TTLSeconds = 60
	}
	c.DenyProjects = append([]string(nil), c.DenyProjects...)
	p := &BWS{config: c, local: New(nil), values: make(map[string]bwsEntry), status: BackendStatus{Configured: true}}
	if c.CacheDir != "" {
		if !filepath.IsAbs(c.CacheDir) {
			return nil, errors.New("bws cache directory must be absolute")
		}
		if e := os.MkdirAll(c.CacheDir, 0700); e != nil {
			return nil, errors.New("bws cache unavailable")
		}
		info, e := os.Lstat(c.CacheDir)
		if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || os.Chmod(c.CacheDir, 0700) != nil {
			return nil, errors.New("bws cache unavailable")
		}
	}
	return p, nil
}
func (p *BWS) Status() BackendStatus { p.mu.Lock(); defer p.mu.Unlock(); return p.status }
func (p *BWS) List(ctx context.Context, scope string) ([]Reference, error) {
	return []Reference{}, ctx.Err()
}
func (p *BWS) Health(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, err := p.loadProjects(ctx, true)
	return err
}
func (p *BWS) denied(names ...string) bool {
	for _, d := range p.config.DenyProjects {
		for _, n := range names {
			if strings.EqualFold(d, n) {
				return true
			}
		}
	}
	return false
}
func parseBWSRef(ref string) (string, string, error) {
	u, e := url.Parse(ref)
	if e != nil || u.Scheme != "bws" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") || len(u.Path) < 2 || strings.Contains(u.EscapedPath()[1:], "/") {
		return "", "", errors.New("invalid bws reference")
	}
	return u.Host, u.Path[1:], nil
}
func (p *BWS) Get(ctx context.Context, ref string) (Secret, error) { return p.get(ctx, ref, false) }

// TestFetch bypasses both value caches and never falls back to stale data.
func (p *BWS) TestFetch(ctx context.Context, ref string) (Secret, error) {
	return p.get(ctx, ref, true)
}
func (p *BWS) get(ctx context.Context, ref string, force bool) (Secret, error) {
	project, key, err := parseBWSRef(ref)
	if err != nil {
		return Secret{}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return Secret{}, err
	}
	if p.denied(project) {
		return Secret{}, ErrDenied
	}
	cached, ok := p.values[ref]
	if !ok {
		cached, ok = p.readCache(ref)
	}
	if ok && p.denied(cached.ProjectID, cached.ProjectName) {
		return Secret{}, ErrDenied
	}
	// Old ID-only caches lack the project name needed to enforce a new
	// name denylist. Fail closed until metadata can be resolved again.
	if ok && len(p.config.DenyProjects) > 0 && cached.ProjectName == "" {
		ok = false
	}
	if !force && ok && time.Since(cached.At) < time.Duration(p.config.TTLSeconds)*time.Second {
		return NewSecret(cached.Value), nil
	}
	id, name, err := p.resolve(ctx, project, force)
	if err == nil && p.denied(id, name) {
		return Secret{}, ErrDenied
	}
	if err == nil {
		var raw []byte
		raw, err = p.run(ctx, "secret", "list", id)
		if err == nil {
			var rows []struct {
				Key       string `json:"key"`
				Value     string `json:"value"`
				ProjectID string `json:"projectId"`
			}
			if json.Unmarshal(raw, &rows) != nil || rows == nil {
				err = p.failure("invalid_json")
			} else {
				value := ""
				matches := 0
				for _, row := range rows {
					if row.Key == key && row.ProjectID == id {
						value = row.Value
						matches++
					}
				}
				if matches > 1 {
					err = p.failure("ambiguous_key")
				} else if value == "" {
					delete(p.values, ref)
					p.removeCache(ref)
					return Secret{}, ErrMissing
				} else {
					entry := bwsEntry{value, id, name, time.Now()}
					p.values[ref] = entry
					if p.writeCache(ref, entry) != nil {
						p.status.LastErrorClass = "cache_io"
					}
					return NewSecret(value), nil
				}
			}
		}
	}
	if errors.Is(err, ErrMissing) {
		delete(p.values, ref)
		p.removeCache(ref)
	}
	// Missing projects, explicit denials and caller cancellation never use LKG.
	if !force && ok && ctx.Err() == nil && !errors.Is(err, ErrMissing) && !errors.Is(err, ErrDenied) {
		return NewSecret(cached.Value), nil
	}
	return Secret{}, err
}
func (p *BWS) resolve(ctx context.Context, project string, force bool) (string, string, error) {
	// With a denylist, resolve IDs too so a denied name cannot be bypassed by ID.
	if projectID.MatchString(project) && len(p.config.DenyProjects) == 0 {
		return strings.ToLower(project), "", nil
	}
	rows, err := p.loadProjects(ctx, force)
	if err != nil {
		return "", "", err
	}
	var found *bwsProject
	for i := range rows {
		if rows[i].Name == project || strings.EqualFold(rows[i].ID, project) {
			if found != nil {
				return "", "", p.failure("ambiguous_project")
			}
			found = &rows[i]
		}
	}
	if found == nil {
		return "", "", ErrMissing
	}
	return found.ID, found.Name, nil
}
func (p *BWS) loadProjects(ctx context.Context, force bool) ([]bwsProject, error) {
	if !force && p.projects != nil && time.Since(p.projectsAt) < time.Duration(p.config.TTLSeconds)*time.Second {
		return p.projects, nil
	}
	raw, err := p.run(ctx, "project", "list")
	if err != nil {
		return nil, err
	}
	var rows []bwsProject
	if json.Unmarshal(raw, &rows) != nil || rows == nil {
		return nil, p.failure("invalid_json")
	}
	for _, row := range rows {
		if !projectID.MatchString(row.ID) || row.Name == "" {
			return nil, p.failure("invalid_json")
		}
	}
	p.projects = rows
	p.projectsAt = time.Now()
	return rows, nil
}
func (p *BWS) failure(class string) error {
	p.status.Reachable = false
	p.status.LastErrorClass = class
	return errors.New("bws: " + class)
}

// cappedOutput prevents unbounded CLI output from accumulating in memory.
type cappedOutput struct{ data []byte }

func (b *cappedOutput) Write(v []byte) (int, error) {
	if len(b.data)+len(v) > 8<<20 {
		return 0, errors.New("output limit")
	}
	b.data = append(b.data, v...)
	return len(v), nil
}
func (p *BWS) run(ctx context.Context, args ...string) ([]byte, error) {
	token, err := p.local.Get(ctx, p.config.TokenRef)
	if err != nil {
		return nil, p.failure("token_unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(p.config.TimeoutSeconds)*time.Second)
	defer cancel()
	args = append(args, "--output", "json", "--server-url", p.config.ServerURL)
	cmd := exec.CommandContext(ctx, p.config.Binary, args...)
	// Remove inherited BWS settings: configuration and authentication are explicit.
	tokenURL, _ := url.Parse(p.config.TokenRef)
	for _, v := range os.Environ() {
		if !strings.HasPrefix(v, "BWS_") && !(tokenURL.Scheme == "env" && strings.HasPrefix(v, tokenURL.Host+"=")) {
			cmd.Env = append(cmd.Env, v)
		}
	}
	cmd.Env = append(cmd.Env, "BWS_ACCESS_TOKEN="+token.Reveal())
	var out cappedOutput
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = 100 * time.Millisecond
	if cmd.Run() != nil {
		if ctx.Err() != nil {
			return nil, p.failure("timeout")
		}
		return nil, p.failure("command_failed")
	}
	p.status.Reachable = true
	p.status.LastErrorClass = ""
	return out.data, nil
}
func (p *BWS) cachePath(ref string) string {
	sum := sha256.Sum256([]byte(p.config.ServerURL + "\x00" + p.config.TokenRef + "\x00" + ref))
	return filepath.Join(p.config.CacheDir, hex.EncodeToString(sum[:])+".json")
}
func (p *BWS) readCache(ref string) (bwsEntry, bool) {
	if p.config.CacheDir == "" {
		return bwsEntry{}, false
	}
	path := p.cachePath(ref)
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return bwsEntry{}, false
	}
	f, e := os.Open(path)
	if e != nil {
		return bwsEntry{}, false
	}
	defer f.Close()
	var entry bwsEntry
	if json.NewDecoder(io.LimitReader(f, 8<<20)).Decode(&entry) != nil || entry.Value == "" || !projectID.MatchString(entry.ProjectID) || entry.At.IsZero() || entry.At.After(time.Now()) {
		return bwsEntry{}, false
	}
	return entry, true
}
func (p *BWS) writeCache(ref string, entry bwsEntry) error {
	if p.config.CacheDir == "" {
		return nil
	}
	raw, e := json.Marshal(entry)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(p.config.CacheDir, ".bws-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.Write(raw)
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), p.cachePath(ref))
}
func (p *BWS) removeCache(ref string) {
	if p.config.CacheDir != "" {
		_ = os.Remove(p.cachePath(ref))
	}
}
