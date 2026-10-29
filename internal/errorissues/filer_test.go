package errorissues

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
	"github.com/teddashh/AI-Intune/internal/store"
)

type fakeGitHub struct {
	issues                               map[string]issue
	creates, comments, reopens, requests int
	bodies                               []string
	disabled                             int
	regression                           bool
}

func (g *fakeGitHub) serve(w http.ResponseWriter, r *http.Request) {
	g.requests++
	if g.disabled != 0 {
		w.WriteHeader(g.disabled)
		return
	}
	b, _ := io.ReadAll(r.Body)
	if errlog.ContainsSecret(string(b)) {
		panic("secret in request")
	}
	g.bodies = append(g.bodies, string(b))
	switch {
	case r.Method == "GET":
		fp := strings.TrimPrefix(r.URL.Query().Get("labels"), "fp:")
		if i, ok := g.issues[fp]; ok {
			json.NewEncoder(w).Encode([]issue{i})
		} else {
			io.WriteString(w, "[]")
		}
	case r.Method == "PATCH":
		g.reopens++
		for fp, i := range g.issues {
			if strings.HasSuffix(r.URL.Path, fmt.Sprint(i.Number)) {
				i.State = "open"
				g.issues[fp] = i
			}
		}
	case strings.HasSuffix(r.URL.Path, "/comments"):
		g.comments++
	case strings.HasSuffix(r.URL.Path, "/labels"):
		if strings.Contains(string(b), "regression") {
			g.regression = true
		}
		w.WriteHeader(201)
	case strings.HasSuffix(r.URL.Path, "/issues"):
		var v struct {
			Labels []string
			Body   string
		}
		json.Unmarshal(b, &v)
		g.creates++
		for _, l := range v.Labels {
			if strings.HasPrefix(l, "fp:") {
				g.issues[strings.TrimPrefix(l, "fp:")] = issue{Number: g.creates, State: "open"}
			}
		}
		w.WriteHeader(201)
	default:
		panic("unexpected request")
	}
}
func setup(t *testing.T) (*Filer, *fakeGitHub, time.Time) {
	t.Helper()
	s, e := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	g := &fakeGitHub{issues: map[string]issue{}}
	server := httptest.NewServer(http.HandlerFunc(g.serve))
	t.Cleanup(server.Close)
	c, _ := FromEnv(func(k string) string {
		if k == "ERROR_ISSUES_ENABLED" {
			return "true"
		}
		return ""
	})
	return &Filer{Config: c, Store: s, GitHub: &Client{BaseURL: server.URL, HTTP: server.Client()}, Logf: func(string, ...any) {}}, g, time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
}
func insert(t *testing.T, f *Filer, now time.Time, fp string, count int) {
	t.Helper()
	_, e := f.Store.InsertErrors(context.Background(), []errlog.Record{{TS: now, MachineID: "machine-1", Component: "intune-agent", Version: "v1", Level: "error", Code: "E42", Msg: "failure password=redactme", Fingerprint: fp, Count: count}})
	if e != nil {
		t.Fatal(e)
	}
}
func run(t *testing.T, f *Filer, now time.Time) {
	t.Helper()
	if e := f.Run(context.Background(), now); e != nil {
		t.Fatal(e)
	}
}
func TestDedupThrottleAndReopen(t *testing.T) {
	f, g, now := setup(t)
	insert(t, f, now, "a", 3)
	run(t, f, now)
	run(t, f, now.Add(time.Minute))
	if g.creates != 1 || g.comments != 0 {
		t.Fatal("dedup failed")
	}
	insert(t, f, now.Add(time.Hour), "a", 3)
	run(t, f, now.Add(time.Hour))
	if g.comments != 0 {
		t.Fatal("comment throttle failed")
	}
	insert(t, f, now.Add(25*time.Hour), "a", 3)
	run(t, f, now.Add(25*time.Hour))
	run(t, f, now.Add(25*time.Hour))
	if g.comments != 1 {
		t.Fatal("expected one update")
	}
	closed := now.Add(26 * time.Hour)
	i := g.issues["a"]
	i.State = "closed"
	i.ClosedAt = &closed
	g.issues["a"] = i
	run(t, f, closed)
	if g.reopens != 0 {
		t.Fatal("old occurrence reopened issue")
	}
	insert(t, f, closed.Add(time.Hour), "a", 3)
	run(t, f, closed.Add(time.Hour))
	if g.reopens != 1 || !g.regression || g.comments != 1 {
		t.Fatal("regression handling failed")
	}
	all := strings.Join(g.bodies, "")
	if strings.Contains(all, "redactme") || !strings.Contains(all, "[REDACTED]") {
		t.Fatal("redaction failed")
	}
}
func TestRateLimitsDigestAndPersistence(t *testing.T) {
	f, g, now := setup(t)
	for n := 0; n < 8; n++ {
		insert(t, f, now, fmt.Sprintf("%02d", n), 3)
	}
	run(t, f, now)
	if g.creates != 5 {
		t.Fatalf("creates=%d", g.creates)
	}
	if _, ok := g.issues["error-overflow-digest"]; !ok {
		t.Fatal("missing digest")
	}
	// A fresh filer shares the persisted counters, and the existing digest is deduped.
	f = &Filer{Config: f.Config, Store: f.Store, GitHub: f.GitHub, Logf: f.Logf}
	run(t, f, now.Add(time.Minute))
	if g.creates != 5 {
		t.Fatal("budget reset")
	}
	for hour := 1; hour < 8; hour++ {
		at := now.Add(time.Duration(hour) * time.Hour)
		for n := 0; n < 8; n++ {
			insert(t, f, at, fmt.Sprintf("%02d-%02d", hour, n), 3)
		}
		run(t, f, at)
	}
	if g.creates != 20 {
		t.Fatalf("daily limit exceeded: %d", g.creates)
	}
}
func TestDisabledRepositories(t *testing.T) {
	for _, status := range []int{404, 410} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			f, g, now := setup(t)
			g.disabled = status
			logs := 0
			f.Logf = func(string, ...any) { logs++ }
			for n := 0; n < 8; n++ {
				insert(t, f, now, fmt.Sprint(n), 3)
			}
			run(t, f, now)
			run(t, f, now)
			if g.requests != 1 || logs != 1 {
				t.Fatalf("requests=%d logs=%d", g.requests, logs)
			}
			for n := 0; n < 4; n++ {
				ok, e := f.Store.ReserveIssue(context.Background(), f.Config.IntuneRepo, now, false)
				if e != nil || !ok {
					t.Fatal("disabled repo consumed budget")
				}
			}
		})
	}
}
func TestDryRunAndOff(t *testing.T) {
	f, g, now := setup(t)
	insert(t, f, now, "a", 3)
	f.Config.DryRun = true
	logs := 0
	f.Logf = func(format string, args ...any) {
		logs++
		if errlog.ContainsSecret(fmt.Sprintf(format, args...)) {
			t.Fatal("unsafe dry run log")
		}
	}
	run(t, f, now)
	if g.requests != 0 || logs != 1 {
		t.Fatal("dry run")
	}
	f.Config.Enabled = false
	f.Store = nil
	run(t, f, now)
	if g.requests != 0 {
		t.Fatal("off")
	}
}
func TestTokenFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	yes := func(os.FileInfo) bool { return true }
	no := func(os.FileInfo) bool { return false }
	if _, e := ReadToken(path, yes); e == nil {
		t.Fatal("missing accepted")
	}
	if e := os.WriteFile(path, []byte("test-credential"), 0600); e != nil {
		t.Fatal(e)
	}
	if v, e := ReadToken(path, yes); e != nil || v != "test-credential" {
		t.Fatal("valid rejected")
	}
	if _, e := ReadToken(path, no); e == nil {
		t.Fatal("owner accepted")
	}
	os.Chmod(path, 0644)
	if _, e := ReadToken(path, yes); e == nil {
		t.Fatal("mode accepted")
	}
	os.Chmod(path, 0600)
	os.WriteFile(path, nil, 0600)
	if _, e := ReadToken(path, yes); e == nil {
		t.Fatal("empty accepted")
	}
}
func TestTokenFilePermissions(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mode   os.FileMode
		owner  bool
		kind   string
		wantOK bool
	}{
		{"0600", 0600, true, "file", true},
		{"0400", 0400, true, "file", true},
		{"0640", 0640, true, "file", false},
		{"0644", 0644, true, "file", false},
		{"0604", 0604, true, "file", false},
		{"0660", 0660, true, "file", false},
		{"0700", 0700, true, "file", false},
		{"setuid", 0600 | os.ModeSetuid, true, "file", false},
		{"setgid", 0600 | os.ModeSetgid, true, "file", false},
		{"sticky", 0600 | os.ModeSticky, true, "file", false},
		{"owner rejected", 0600, false, "file", false},
		{"directory", 0600, true, "directory", false},
		{"non-regular", 0600, true, "device", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			switch tc.kind {
			case "directory":
				if err := os.Mkdir(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			case "device":
				path = "/dev/null"
			default:
				if err := os.WriteFile(path, []byte("test-credential"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(path, tc.mode); err != nil {
					t.Fatal(err)
				}
			}
			token, err := ReadToken(path, func(os.FileInfo) bool { return tc.owner })
			if tc.wantOK {
				if err != nil || token != "test-credential" {
					t.Fatalf("valid token rejected: %v", err)
				}
			} else if err == nil || err.Error() != "issue token file must be owned by root or the service user with mode 0600 or 0400" {
				t.Fatalf("expected ownership/mode rejection, got %v", err)
			}
		})
	}
}

func TestOwnerRootOrSelf(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("test-credential"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !OwnerRootOrSelf(info) {
		t.Fatal("test process owner rejected")
	}
}

func TestRoutingAndThresholds(t *testing.T) {
	f, g, now := setup(t)
	insert(t, f, now, "below", 1)
	run(t, f, now)
	if g.creates != 0 {
		t.Fatal("below threshold")
	}
	_, e := f.Store.InsertErrors(context.Background(), []errlog.Record{{TS: now, MachineID: "machine-2", Component: "intune-agent", Level: "error", Fingerprint: "below", Count: 1}, {TS: now, MachineID: "m", Component: "bat-session", Level: "warn", Fingerprint: "warn", Count: 99}})
	if e != nil {
		t.Fatal(e)
	}
	run(t, f, now)
	if g.creates != 1 {
		t.Fatal("machine threshold")
	}
	for _, c := range []string{"bat-connector", "bat-tunnel", "bat-session", "fleet-monitor", "bat-server"} {
		if f.route(c) != f.Config.BATRepo {
			t.Fatal(c)
		}
	}
	if f.route("unknown") != "" {
		t.Fatal("unknown route")
	}
}

func TestSanitizer(t *testing.T) {
	for _, text := range []string{"Bearer token=value", "ghp_privatevalue", "person@example.com", "password=hidden"} {
		sanitized, err := safe(text)
		if err != nil || errlog.ContainsSecret(sanitized) || sanitized == text {
			t.Fatal("sanitizer failed")
		}
	}
}
func TestRepoFailureReleasesBudget(t *testing.T) {
	f, g, now := setup(t)
	insert(t, f, now, "fp", 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			io.WriteString(w, "[]")
			return
		}
		if strings.HasSuffix(r.URL.Path, "/labels") {
			w.WriteHeader(422)
			return
		}
		w.WriteHeader(410)
	}))
	defer server.Close()
	f.GitHub.BaseURL = server.URL
	run(t, f, now)
	f.GitHub.BaseURL = "invalid"
	run(t, f, now) // unavailable repo stays skipped
	for n := 0; n < 4; n++ {
		ok, e := f.Store.ReserveIssue(context.Background(), f.Config.IntuneRepo, now, false)
		if e != nil || !ok {
			t.Fatal("failed creation consumed budget")
		}
	}
	if g.requests != 0 {
		t.Fatal("unexpected request")
	}
}
func TestBudgetSurvivesDatabaseReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	ctx := context.Background()
	now := time.Now()
	s, e := store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = s.InitIssueFiler(ctx); e != nil {
		t.Fatal(e)
	}
	for n := 0; n < 4; n++ {
		ok, e := s.ReserveIssue(ctx, "owner/repo", now, false)
		if e != nil || !ok {
			t.Fatal("reserve failed")
		}
	}
	if e = s.SaveIssueAction(ctx, "owner/repo", "fp", "seen", now); e != nil {
		t.Fatal(e)
	}
	s.Close()
	s, e = store.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	if ok, e := s.ReserveIssue(ctx, "owner/repo", now, false); e != nil || ok {
		t.Fatal("budget reset on reopen")
	}
	if seen, _, e := s.IssueAction(ctx, "owner/repo", "fp"); e != nil || seen != "seen" {
		t.Fatal("action reset on reopen")
	}
	if ok, e := s.ReserveIssue(ctx, "owner/other", now, false); e != nil || !ok {
		t.Fatal("repo budgets not independent")
	}
	if ok, e := s.ReserveIssue(ctx, "owner/repo", now.Add(25*time.Hour), false); e != nil || !ok {
		t.Fatal("budget failed to expire")
	}
}

func TestConfig(t *testing.T) {
	c, e := FromEnv(func(string) string { return "" })
	if e != nil || c.Enabled || c.DryRun || c.Interval != 15*time.Minute {
		t.Fatal("defaults")
	}
	values := map[string]string{"ERROR_ISSUES_ENABLED": "true", "ERROR_ISSUES_DRY_RUN": "true", "ERROR_ISSUES_INTERVAL": "2m", "ERROR_ISSUES_INTUNE_REPO": "custom/intune", "ERROR_ISSUES_BAT_REPO": "custom/bat"}
	c, e = FromEnv(func(k string) string { return values[k] })
	if e != nil || !c.Enabled || !c.DryRun || c.Interval != 2*time.Minute || c.IntuneRepo != "custom/intune" || c.BATRepo != "custom/bat" {
		t.Fatal("configuration")
	}
	for _, v := range []string{"0s", "-1m", "invalid"} {
		values["ERROR_ISSUES_INTERVAL"] = v
		if _, e := FromEnv(func(k string) string { return values[k] }); e == nil {
			t.Fatal("invalid interval accepted")
		}
	}
}
func TestSecretIdentityRefused(t *testing.T) {
	f, g, now := setup(t)
	insert(t, f, now, "ghp_privatevalue", 3)
	if e := f.Run(context.Background(), now); e == nil {
		t.Fatal("unsafe identity accepted")
	}
	if g.requests != 0 {
		t.Fatal("secret identity sent to GitHub")
	}
}
func TestContentAndSampleLimit(t *testing.T) {
	f, g, now := setup(t)
	for n := 0; n < 8; n++ {
		_, e := f.Store.InsertErrors(context.Background(), []errlog.Record{{TS: now.Add(-time.Duration(n) * time.Minute), MachineID: fmt.Sprintf("machine-%d", n), Fingerprint: "sample", Component: "intune-agent", Code: "E42", Version: "v1", Level: "error", Count: 1, Msg: fmt.Sprintf("sample-%d secret=hidden", n), Context: map[string]any{"hostname": "private-host"}}})
		if e != nil {
			t.Fatal(e)
		}
	}
	run(t, f, now)
	var v struct {
		Body   string
		Labels []string
	}
	for _, b := range g.bodies {
		var x struct {
			Body   string
			Labels []string
		}
		json.Unmarshal([]byte(b), &x)
		if x.Body != "" {
			v = x
		}
	}
	if strings.Count(v.Body, "sample-") != 5 || strings.Contains(v.Body, "private-host") || strings.Contains(v.Body, "hidden") {
		t.Fatal("content policy failed")
	}
	for _, want := range []string{"<!-- fp:sample -->", "E42", "intune-agent", "v1", "Machine IDs:", "First seen:", "Last seen:", "Occurrences (24h): 8"} {
		if !strings.Contains(v.Body, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Join(v.Labels, ",") != "auto-filed,component:intune-agent,fp:sample" {
		t.Fatal("labels")
	}
}

func TestDigestReopensOnlyOnNewEvidence(t *testing.T) {
	f, g, now := setup(t)
	for n := 0; n < 8; n++ {
		insert(t, f, now, fmt.Sprint(n), 3)
	}
	run(t, f, now)
	closed := now.Add(time.Minute)
	i := g.issues["error-overflow-digest"]
	i.State = "closed"
	i.ClosedAt = &closed
	g.issues["error-overflow-digest"] = i
	run(t, f, now.Add(2*time.Minute))
	if g.reopens != 0 {
		t.Fatal("old overflow reopened digest")
	}
	insert(t, f, now.Add(3*time.Minute), "7", 3)
	run(t, f, now.Add(3*time.Minute))
	if g.reopens != 1 {
		t.Fatal("new overflow did not reopen digest")
	}
}
