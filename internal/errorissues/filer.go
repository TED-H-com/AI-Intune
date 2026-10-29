// Package errorissues promotes recurring fleet errors to GitHub issues.
package errorissues

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
	"github.com/teddashh/AI-Intune/internal/store"
)

type Config struct {
	Enabled, DryRun                bool
	Interval                       time.Duration
	TokenFile, IntuneRepo, BATRepo string
}

func FromEnv(get func(string) string) (Config, error) {
	c := Config{Enabled: get("ERROR_ISSUES_ENABLED") == "true", DryRun: get("ERROR_ISSUES_DRY_RUN") == "true", Interval: 15 * time.Minute, TokenFile: get("ERROR_ISSUES_TOKEN_FILE"), IntuneRepo: get("ERROR_ISSUES_INTUNE_REPO"), BATRepo: get("ERROR_ISSUES_BAT_REPO")}
	if c.IntuneRepo == "" {
		c.IntuneRepo = "TED-H-com/AI-Intune"
	}
	if c.BATRepo == "" {
		c.BATRepo = "TED-H-com/bat-agent-connector"
	}
	if c.Enabled {
		if v := get("ERROR_ISSUES_INTERVAL"); v != "" {
			d, e := time.ParseDuration(v)
			if e != nil || d <= 0 {
				return c, errors.New("invalid ERROR_ISSUES_INTERVAL")
			}
			c.Interval = d
		}
	}
	return c, nil
}

// OwnerRoot can be substituted in tests on hosts without uid 0.
func OwnerRoot(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
func ReadToken(path string, owner func(os.FileInfo) bool) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", errors.New("issue token file unavailable")
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Mode() != 0600 || !owner(info) {
		return "", errors.New("issue token file requires root ownership and mode 0600")
	}
	b, e := io.ReadAll(io.LimitReader(f, 16385))
	if e != nil || len(b) > 16384 || strings.TrimSpace(string(b)) == "" {
		return "", errors.New("invalid issue token file")
	}
	return strings.TrimSpace(string(b)), nil
}

type Client struct {
	BaseURL, Token string
	HTTP           *http.Client
}

type statusError int

func (e statusError) Error() string { return fmt.Sprintf("GitHub status %d", int(e)) }
func (c *Client) ensureLabels(ctx context.Context, repo string, labels []string) error {
	for _, label := range labels {
		err := c.call(ctx, "POST", "/repos/"+repo+"/labels", map[string]string{"name": label, "color": "d73a4a"}, nil)
		if err != nil && err != statusError(422) {
			return err
		}
	}
	return nil
}

var errDisabled = errors.New("repository issues unavailable")

func (c *Client) call(ctx context.Context, method, path string, in, out any) error {
	var b bytes.Buffer
	if in != nil {
		if e := json.NewEncoder(&b).Encode(in); e != nil {
			return e
		}
	}
	base := c.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	req, e := http.NewRequestWithContext(ctx, method, strings.TrimRight(base, "/")+path, &b)
	if e != nil {
		return errors.New("invalid GitHub endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("GitHub request failed")
	}
	defer res.Body.Close()
	if res.StatusCode == 404 || res.StatusCode == 410 {
		return errDisabled
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return statusError(res.StatusCode)
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(out)
	}
	return nil
}

type issue struct {
	Number      int             `json:"number"`
	State       string          `json:"state"`
	ClosedAt    *time.Time      `json:"closed_at"`
	PullRequest json.RawMessage `json:"pull_request"`
}

func (c *Client) find(ctx context.Context, repo, fp string) (*issue, error) {
	for page := 1; ; page++ {
		var list []issue
		e := c.call(ctx, "GET", fmt.Sprintf("/repos/%s/issues?state=all&labels=%s&per_page=100&page=%d", repo, url.QueryEscape("fp:"+fp), page), nil, &list)
		if e != nil {
			return nil, e
		}
		for _, i := range list {
			if len(i.PullRequest) == 0 || string(i.PullRequest) == "null" {
				return &i, nil
			}
		}
		if len(list) < 100 {
			return nil, nil
		}
	}
}

type Filer struct {
	Config   Config
	Store    *store.Store
	GitHub   *Client
	Logf     func(string, ...any)
	disabled map[string]bool
}

func (f *Filer) log(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	} else {
		log.Printf(format, args...)
	}
}
func (f *Filer) route(component string) string {
	if strings.HasPrefix(component, "intune") {
		return f.Config.IntuneRepo
	}
	switch component {
	case "bat-connector", "bat-tunnel", "bat-session", "fleet-monitor", "bat-server":
		return f.Config.BATRepo
	}
	return ""
}

type aggregate struct {
	fp, component, code string
	first, last         time.Time
	count               int
	machines, versions  map[string]bool
	samples             []string
}

func keys(m map[string]bool) []string {
	r := make([]string, 0, len(m))
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func (a *aggregate) body() string {
	return fmt.Sprintf("<!-- fp:%s -->\nCode: %s\nComponent: %s\nVersions: %s\nMachine IDs: %s\nOccurrences (24h): %d\nFirst seen: %s\nLast seen: %s\nSamples:\n%s", a.fp, a.code, a.component, strings.Join(keys(a.versions), ", "), strings.Join(keys(a.machines), ", "), a.count, a.first.UTC().Format(time.RFC3339Nano), a.last.UTC().Format(time.RFC3339Nano), strings.Join(a.samples, "\n"))
}
func safe(s string) (string, error) {
	s = errlog.Redact(s)
	if errlog.ContainsSecret(s) {
		return "", errors.New("issue content rejected")
	}
	return s, nil
}
func (f *Filer) Run(ctx context.Context, now time.Time) error {
	if !f.Config.Enabled {
		return nil
	}
	if f.disabled == nil {
		f.disabled = map[string]bool{}
	}
	if e := f.Store.InitIssueFiler(ctx); e != nil {
		return e
	}
	records, e := f.Store.IssueErrors(ctx, now.Add(-24*time.Hour))
	if e != nil {
		return e
	}
	groups := map[string]*aggregate{}
	for _, r := range records {
		if r.Level != "error" || r.TS.After(now) || f.route(r.Component) == "" {
			continue
		}
		a := groups[r.Fingerprint]
		if a == nil {
			a = &aggregate{fp: r.Fingerprint, component: r.Component, code: r.Code, first: r.TS, machines: map[string]bool{}, versions: map[string]bool{}}
			groups[r.Fingerprint] = a
		}
		a.last = r.TS
		a.count += r.Count
		a.machines[r.MachineID] = true
		a.versions[r.Version] = true
		if len(a.samples) < 5 {
			a.samples = append(a.samples, strings.ReplaceAll(r.Msg, "\n", " "))
		}
	}
	fps := make([]string, 0, len(groups))
	for fp := range groups {
		fps = append(fps, fp)
	}
	sort.Strings(fps)
	overflow := map[string][]string{}
	overflowSamples := map[string][]string{}
	overflowLast := map[string]time.Time{}
	var errs []error
	for _, fp := range fps {
		a := groups[fp]
		if a.count < 3 && len(a.machines) < 2 {
			continue
		}
		repo := f.route(a.component)
		if f.disabled[repo] {
			continue
		}
		title := fmt.Sprintf("%s: %s [%s]", a.component, a.code, fp)
		over, err := f.file(ctx, now, repo, fp, title, a.body(), a.last, []string{"auto-filed", "component:" + a.component, "fp:" + fp}, false)
		if errors.Is(err, errDisabled) {
			f.disabled[repo] = true
			f.log("error issues: repo=%s issues unavailable", errlog.Redact(repo))
		} else if err != nil {
			errs = append(errs, err)
		}
		if over {
			if a.last.After(overflowLast[repo]) {
				overflowLast[repo] = a.last
			}
			overflow[repo] = append(overflow[repo], strings.SplitN(a.body(), "\nSamples:\n", 2)[0])
			for _, sample := range a.samples {
				if len(overflowSamples[repo]) >= 5 {
					break
				}
				overflowSamples[repo] = append(overflowSamples[repo], sample)
			}
		}
	}
	repos := keysMap(overflow)
	for _, repo := range repos {
		if f.disabled[repo] {
			continue
		}
		_, err := f.file(ctx, now, repo, "error-overflow-digest", "Fleet error overflow digest", "<!-- fp:error-overflow-digest -->\n"+strings.Join(overflow[repo], "\n\n")+"\nSamples:\n"+strings.Join(overflowSamples[repo], "\n"), overflowLast[repo], []string{"auto-filed", "fp:error-overflow-digest"}, true)
		if errors.Is(err, errDisabled) {
			f.disabled[repo] = true
			f.log("error issues: repo=%s issues unavailable", errlog.Redact(repo))
		} else if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
func keysMap(m map[string][]string) []string {
	var r []string
	for k := range m {
		r = append(r, k)
	}
	sort.Strings(r)
	return r
}
func (f *Filer) file(ctx context.Context, now time.Time, repo, fp, title, body string, last time.Time, labels []string, digest bool) (bool, error) {
	var e error
	if errlog.Redact(repo) != repo || errlog.Redact(fp) != fp || errlog.ContainsSecret(repo) || errlog.ContainsSecret(fp) {
		return false, errors.New("issue identity rejected")
	}
	title, e = safe(title)
	if e != nil {
		return false, e
	}
	body, e = safe(body)
	if e != nil {
		return false, e
	}
	for i := range labels {
		labels[i], e = safe(labels[i])
		if e != nil {
			return false, e
		}
	}
	if f.Config.DryRun {
		f.log("error issues dry-run: repo=%s fingerprint=%s actions=lookup,file,comment-or-reopen title=%s body=%s", errlog.Redact(repo), errlog.Redact(fp), title, body)
		return false, nil
	}
	existing, e := f.GitHub.find(ctx, repo, fp)
	if e != nil {
		return false, e
	}
	seen, comment, e := f.Store.IssueAction(ctx, repo, fp)
	if e != nil {
		return false, e
	}
	seenAt, _ := time.Parse(time.RFC3339Nano, seen)
	commentAt, _ := time.Parse(time.RFC3339Nano, comment)
	action := "created"
	if existing != nil {
		action = "commented"
		path := fmt.Sprintf("/repos/%s/issues/%d", repo, existing.Number)
		if existing.State == "closed" {
			action = "reopened"
			cutoff := seenAt
			if existing.ClosedAt != nil && existing.ClosedAt.After(cutoff) {
				cutoff = *existing.ClosedAt
			}
			if !last.After(cutoff) {
				return false, nil
			}
			if e = f.GitHub.ensureLabels(ctx, repo, []string{"regression"}); e != nil {
				return false, e
			}
			if e = f.GitHub.call(ctx, "POST", path+"/labels", map[string]any{"labels": []string{"regression"}}, nil); e != nil {
				return false, e
			}
			if e = f.GitHub.call(ctx, "PATCH", path, map[string]any{"state": "open"}, nil); e != nil {
				return false, e
			}
		}
		if !last.After(seenAt) || now.Sub(commentAt) < 24*time.Hour {
			if action == "reopened" {
				return false, f.finish(ctx, repo, fp, last, commentAt, now, action)
			}
			return false, nil
		}
		if e = f.GitHub.call(ctx, "POST", path+"/comments", map[string]string{"body": body}, nil); e != nil {
			return false, e
		}
	} else {
		allowed, err := f.Store.ReserveIssue(ctx, repo, now, digest)
		if err != nil {
			return false, err
		}
		if !allowed {
			return true, nil
		}
		e = f.GitHub.ensureLabels(ctx, repo, labels)
		if e == nil {
			e = f.GitHub.call(ctx, "POST", "/repos/"+repo+"/issues", map[string]any{"title": title, "body": body, "labels": labels}, nil)
		}
		if e != nil {
			if release := f.Store.ReleaseIssue(ctx, repo, now, digest); release != nil {
				return false, errors.Join(e, release)
			}
			return false, e
		}
	}
	return false, f.finish(ctx, repo, fp, last, now, now, action)
}
func (f *Filer) finish(ctx context.Context, repo, fp string, last, commentAt, now time.Time, action string) error {
	if e := f.Store.SaveIssueAction(ctx, repo, fp, last.UTC().Format(time.RFC3339Nano), commentAt); e != nil {
		return e
	}
	receipt, _ := json.Marshal(map[string]any{"repo": errlog.Redact(repo), "fingerprint": errlog.Redact(fp), "last_seen": last.UTC().Format(time.RFC3339Nano), "action": action})
	return f.Store.RecordHubEvent("error_issue_updated", string(receipt), now)
}
