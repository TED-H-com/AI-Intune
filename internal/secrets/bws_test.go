package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testProjectID = "11111111-1111-1111-1111-111111111111"
const testDeniedID = "22222222-2222-2222-2222-222222222222"

func fakeBWS(t *testing.T) (*BWS, string) {
	t.Helper()
	dir := t.TempDir()
	binary := filepath.Join(dir, "bws")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_BWS_DIR/calls"
case "$*" in *token-sentinel*) exit 90;; esac
[ "$BWS_ACCESS_TOKEN" = token-sentinel ] || exit 91
[ -z "$TEST_BWS_TOKEN" ] || exit 93
case "$*" in *'--server-url https://vault.bitwarden.eu'*) ;; *) exit 92;; esac
if [ -f "$TEST_BWS_DIR/fail" ]; then echo 'token-sentinel value-sentinel' >&2; exit 1; fi
if [ -f "$TEST_BWS_DIR/slow" ]; then exec sleep 5; fi
if [ -f "$TEST_BWS_DIR/malformed" ]; then echo 'value-sentinel'; exit 0; fi
if [ "$1" = project ]; then
 echo '[{"id":"11111111-1111-1111-1111-111111111111","name":"Shared"},{"id":"22222222-2222-2222-2222-222222222222","name":"Confidential"}]'
else
 cat "$TEST_BWS_DIR/values"
fi
`
	if e := os.WriteFile(binary, []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("TEST_BWS_DIR", dir)
	t.Setenv("TEST_BWS_TOKEN", "token-sentinel")
	// Inherited credentials must never override the referenced credential.
	t.Setenv("BWS_ACCESS_TOKEN", "wrong-token")
	writeTestFile(t, filepath.Join(dir, "values"), `[{"key":"KEY","value":"value-sentinel","projectId":"`+testProjectID+`"}]`)
	p, e := NewBWS(BWSConfig{Binary: binary, ServerURL: "https://vault.bitwarden.eu", TokenRef: "env://TEST_BWS_TOKEN", TimeoutSeconds: 1, TTLSeconds: 60, CacheDir: filepath.Join(dir, "cache")})
	if e != nil {
		t.Fatal(e)
	}
	return p, dir
}
func writeTestFile(t *testing.T, path, value string) {
	t.Helper()
	if e := os.WriteFile(path, []byte(value), 0600); e != nil {
		t.Fatal(e)
	}
}
func assertSafe(t *testing.T, values ...any) {
	t.Helper()
	for _, v := range values {
		out := fmt.Sprint(v)
		for _, secret := range []string{"token-sentinel", "value-sentinel"} {
			if strings.Contains(out, secret) {
				t.Fatal("secret leaked")
			}
		}
	}
}
func TestBWSResolutionAndCache(t *testing.T) {
	p, dir := fakeBWS(t)
	ctx := context.Background()
	ref := "bws://Shared/KEY"
	value, e := p.Get(ctx, ref)
	if e != nil || value.Reveal() != "value-sentinel" {
		t.Fatalf("fetch: %v", e)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if strings.Count(string(calls), "project list") != 1 || !strings.Contains(string(calls), "secret list "+testProjectID+" --output json") {
		t.Fatal("unexpected commands")
	}
	assertSafe(t, string(calls), value, p.Status(), p)
	writeTestFile(t, filepath.Join(dir, "fail"), "")
	if _, e = p.Get(ctx, ref); e != nil {
		t.Fatal(e)
	}
	next, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if string(next) != string(calls) {
		t.Fatal("TTL missed")
	}
	// A second key uses cached project metadata, never organization-wide values.
	if _, e = p.TestFetch(ctx, "bws://"+testProjectID+"/KEY"); e == nil {
		t.Fatal("expected fresh failure")
	}
	p.mu.Lock()
	entry := p.values[ref]
	entry.At = time.Now().Add(-2 * time.Minute)
	p.values[ref] = entry
	p.mu.Unlock()
	value, e = p.Get(ctx, ref)
	if e != nil || value.Reveal() != "value-sentinel" {
		t.Fatal("memory LKG failed")
	}
	if p.Status().Reachable || p.Status().LastErrorClass != "command_failed" {
		t.Fatal("outage not reported")
	}
	assertSafe(t, p.Status(), p.Health(ctx))
	// New process, expired on-disk LKG.
	if e = p.writeCache(ref, entry); e != nil {
		t.Fatal(e)
	}
	q, e := NewBWS(p.config)
	if e != nil {
		t.Fatal(e)
	}
	value, e = q.Get(ctx, ref)
	if e != nil || value.Reveal() != "value-sentinel" {
		t.Fatal("disk LKG failed")
	}
	for path, want := range map[string]os.FileMode{p.config.CacheDir: 0700, p.cachePath(ref): 0600} {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != want {
			t.Fatal("cache permissions")
		}
	}
	if e = os.Chmod(p.cachePath(ref), 0644); e != nil {
		t.Fatal(e)
	}
	q, _ = NewBWS(p.config)
	if _, e = q.Get(ctx, ref); e == nil {
		t.Fatal("accepted public cache")
	}
}
func TestBWSFailures(t *testing.T) {
	for _, kind := range []string{"fail", "malformed", "slow"} {
		t.Run(kind, func(t *testing.T) {
			p, dir := fakeBWS(t)
			writeTestFile(t, filepath.Join(dir, kind), "")
			start := time.Now()
			_, e := p.Get(context.Background(), "bws://Shared/KEY")
			if e == nil {
				t.Fatal("accepted failure")
			}
			assertSafe(t, e, p.Status())
			if kind == "slow" && (time.Since(start) > 3*time.Second || p.Status().LastErrorClass != "timeout") {
				t.Fatal("timeout did not kill command")
			}
		})
	}
}
func TestBWSDenylistAliases(t *testing.T) {
	for _, denied := range []string{"Confidential", testDeniedID} {
		for _, project := range []string{"Confidential", testDeniedID} {
			t.Run(denied+project, func(t *testing.T) {
				p, dir := fakeBWS(t)
				p.config.DenyProjects = []string{denied}
				_, e := p.Get(context.Background(), "bws://"+project+"/KEY")
				if !errors.Is(e, ErrDenied) {
					t.Fatalf("deny: %v", e)
				}
				calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
				if strings.Contains(string(calls), "secret list") {
					t.Fatal("denied values requested")
				}
			})
		}
	}
	p, dir := fakeBWS(t)
	ref := "bws://Shared/KEY"
	if _, e := p.Get(context.Background(), ref); e != nil {
		t.Fatal(e)
	}
	p.config.DenyProjects = []string{testProjectID}
	writeTestFile(t, filepath.Join(dir, "fail"), "")
	q, _ := NewBWS(p.config)
	if _, e := q.Get(context.Background(), ref); !errors.Is(e, ErrDenied) {
		t.Fatal("cached deny bypass")
	}
}
func TestBWSMissingRevokesCacheAndTestFetch(t *testing.T) {
	p, dir := fakeBWS(t)
	ref := "bws://Shared/KEY"
	ctx := context.Background()
	if _, e := p.Get(ctx, ref); e != nil {
		t.Fatal(e)
	}
	writeTestFile(t, filepath.Join(dir, "values"), `[]`)
	if _, e := p.TestFetch(ctx, ref); !errors.Is(e, ErrMissing) {
		t.Fatal("fresh test did not see removal")
	}
	writeTestFile(t, filepath.Join(dir, "fail"), "")
	if _, e := p.Get(ctx, ref); e == nil {
		t.Fatal("removed value revived")
	}
	if _, e := os.Stat(p.cachePath(ref)); !os.IsNotExist(e) {
		t.Fatal("disk cache not removed")
	}
}
func TestBWSIDAndTokenFile(t *testing.T) {
	p, dir := fakeBWS(t)
	tokenFile := filepath.Join(dir, "token.env")
	writeTestFile(t, tokenFile, "TOKEN=token-sentinel\n")
	p.config.TokenRef = FileReference(tokenFile, "TOKEN")
	t.Setenv("TEST_BWS_TOKEN", "")
	if _, e := p.Get(context.Background(), "bws://"+testProjectID+"/KEY"); e != nil {
		t.Fatal(e)
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if strings.Contains(string(calls), "project list") {
		t.Fatal("direct id did lookup")
	}
	assertSafe(t, string(calls))
}
func TestBWSConfigurationAndValidation(t *testing.T) {
	for _, c := range []BWSConfig{{TokenRef: "bws://p/k"}, {TokenRef: "env://TOKEN", ServerURL: "https://user:password@example.com"}, {TokenRef: "env://TOKEN", TimeoutSeconds: -1}} {
		if _, e := NewBWS(c); e == nil {
			t.Fatal("invalid config accepted")
		}
	}
	p, dir := fakeBWS(t)
	for _, ref := range []string{"bws://Shared/", "bws://Shared/KEY?x=y", "bws://Shared/KEY#x", "bws://u@Shared/KEY", "bws://Shared/a/b"} {
		if _, e := p.Get(context.Background(), ref); e == nil {
			t.Fatal("invalid ref")
		}
	}
	if _, e := os.Stat(filepath.Join(dir, "calls")); !os.IsNotExist(e) {
		t.Fatal("invalid ref invoked CLI")
	}
	raw, _ := json.Marshal(Config{References: []Reference{{"example", "bws://Shared/KEY"}}, BWS: &p.config})
	file := filepath.Join(dir, "config.json")
	writeTestFile(t, file, string(raw))
	r, e := LoadConfig(file, nil)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.TestFetch(context.Background(), "bws://Shared/KEY"); e != nil {
		t.Fatal(e)
	}
	if !r.BWSStatus().Configured || !r.BWSStatus().Reachable {
		t.Fatal("status")
	}
}

func TestBWSRefreshAndProjectTTL(t *testing.T) {
	p, dir := fakeBWS(t)
	ctx := context.Background()
	ref := "bws://Shared/KEY"
	if _, e := p.Get(ctx, ref); e != nil {
		t.Fatal(e)
	}
	// Project lookup remains cached while a different key is requested.
	if _, e := p.Get(ctx, "bws://Shared/ABSENT"); !errors.Is(e, ErrMissing) {
		t.Fatal("missing key")
	}
	calls, _ := os.ReadFile(filepath.Join(dir, "calls"))
	if strings.Count(string(calls), "project list") != 1 {
		t.Fatal("project TTL missed")
	}
	writeTestFile(t, filepath.Join(dir, "values"), `[{"key":"KEY","value":"rotated","projectId":"`+testProjectID+`"}]`)
	p.mu.Lock()
	entry := p.values[ref]
	entry.At = time.Now().Add(-2 * time.Minute)
	p.values[ref] = entry
	p.projectsAt = entry.At
	p.mu.Unlock()
	value, e := p.Get(ctx, ref)
	if e != nil || value.Reveal() != "rotated" {
		t.Fatal("expired value not refreshed")
	}
	calls, _ = os.ReadFile(filepath.Join(dir, "calls"))
	if strings.Count(string(calls), "project list") != 2 {
		t.Fatal("expired metadata not refreshed")
	}
}
func TestBWSNewDenylistRejectsUnnamedIDCache(t *testing.T) {
	p, dir := fakeBWS(t)
	ref := "bws://" + testProjectID + "/KEY"
	if _, e := p.Get(context.Background(), ref); e != nil {
		t.Fatal(e)
	}
	p.config.DenyProjects = []string{"Shared"}
	q, e := NewBWS(p.config)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = q.Get(context.Background(), ref); !errors.Is(e, ErrDenied) {
		t.Fatal("new name deny bypassed through old ID cache")
	}
	writeTestFile(t, filepath.Join(dir, "fail"), "")
	q, _ = NewBWS(p.config)
	if _, e = q.Get(context.Background(), ref); e == nil {
		t.Fatal("unverified ID cache used offline with name denylist")
	}
}
func TestBWSCancellationAndDuplicateKeys(t *testing.T) {
	p, dir := fakeBWS(t)
	ctx := context.Background()
	ref := "bws://Shared/KEY"
	if _, e := p.Get(ctx, ref); e != nil {
		t.Fatal(e)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := p.Get(canceled, ref); !errors.Is(e, context.Canceled) {
		t.Fatal("cancellation used cache")
	}
	writeTestFile(t, filepath.Join(dir, "values"), `[{"key":"KEY","value":"value-sentinel","projectId":"`+testProjectID+`"},{"key":"KEY","value":"value-sentinel","projectId":"`+testProjectID+`"}]`)
	if _, e := p.TestFetch(ctx, ref); e == nil {
		t.Fatal("ambiguous keys accepted")
	} else {
		assertSafe(t, e, p.Status())
	}
}
