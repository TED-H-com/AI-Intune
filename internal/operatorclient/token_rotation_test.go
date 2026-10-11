package operatorclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestServiceTokenAtomicReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "token")
	old := "cst_" + strings.Repeat("a", 64)
	next := "cst_" + strings.Repeat("b", 64)
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := replaceServiceTokenFile(path, old, next); err != nil {
		t.Fatal(err)
	}
	got, err := ReadServiceTokenFile(path)
	if err != nil || got != next {
		t.Fatal("replacement failed")
	}
	after, _ := os.Stat(path)
	if os.SameFile(before, after) || after.Mode().Perm() != 0600 {
		t.Fatal("not atomic or unsafe mode")
	}
	if err = replaceServiceTokenFile(path, old, next); err == nil {
		t.Fatal("stale credential replaced")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if err = replaceServiceTokenFile(path, next, old); err == nil {
		t.Fatal("unsafe permissions accepted")
	}
	os.Remove(path)
	if err = os.Symlink(filepath.Join(dir, "target"), path); err != nil {
		t.Fatal(err)
	}
	if err = replaceServiceTokenFile(path, next, old); err == nil {
		t.Fatal("symlink accepted")
	}
	files, _ := filepath.Glob(filepath.Join(dir, ".service-token-*"))
	if len(files) != 3 {
		t.Fatal("failed replacements must keep recovery files")
	}
	for _, file := range files {
		if _, err := ReadServiceTokenFile(file); err != nil {
			t.Fatal("unsafe recovery file", err)
		}
	}
}
func TestServiceTokenRotationDuration(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{{"14d", 14 * 24 * time.Hour}, {"1h", time.Hour}, {"0d", 0}} {
		got, err := ParseRotationDuration(tc.raw)
		if err != nil || got != tc.want {
			t.Fatal(tc.raw, got, err)
		}
	}
	for _, raw := range []string{"-1d", "invalid", "999999999999d"} {
		if _, err := ParseRotationDuration(raw); err == nil {
			t.Fatal("invalid accepted")
		}
	}
}

// This integration test needs loopback sockets; retain it for CI/host runs.
func TestServiceTokenRotationHTTPThreshold(t *testing.T) {
	old := "cst_" + strings.Repeat("a", 64)
	next := "cst_" + strings.Repeat("b", 64)
	rotations := 0
	expiry := time.Now().Add(30 * 24 * time.Hour)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+old && !(r.URL.Path == "/v1/operator/service-tokens/self" && r.Header.Get("Authorization") == "Bearer "+next) {
			t.Error("wrong credential")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/operator/service-tokens/self":
			json.NewEncoder(w).Encode(ServiceTokenSelf{ID: "test-id", ExpiresAt: expiry})
		case "/v1/operator/service-tokens/rotate":
			rotations++
			json.NewEncoder(w).Encode(map[string]string{"token": next})
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	base, _ := url.Parse(server.URL)
	client := &Client{base: base, token: old, http: server.Client()}
	if changed, err := client.RotateTokenFile(context.Background(), path, 14*24*time.Hour, false); err != nil || changed || rotations != 0 {
		t.Fatal("not due", err)
	}
	expiry = time.Now().Add(13 * 24 * time.Hour)
	if changed, err := client.RotateTokenFile(context.Background(), path, 14*24*time.Hour, false); err != nil || !changed || rotations != 1 {
		t.Fatal("due", err)
	}
	actual, err := ReadServiceTokenFile(path)
	if err != nil || actual != next {
		t.Fatal("new token not saved")
	}
	if err = os.WriteFile(path, []byte(old), 0600); err != nil {
		t.Fatal(err)
	}
	client.token = old
	expiry = time.Now().Add(30 * 24 * time.Hour)
	if changed, err := client.RotateTokenFile(context.Background(), path, 14*24*time.Hour, true); err != nil || !changed || rotations != 2 {
		t.Fatal("force", err)
	}

}

func TestServiceTokenReplacementFailureRecovery(t *testing.T) {
	for _, failure := range []string{"rename", "file-fsync", "dir-fsync", "crash"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			old := "cst_" + strings.Repeat("a", 64)
			next := "cst_" + strings.Repeat("b", 64)
			if err := os.WriteFile(path, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			ops := defaultTokenFileOps()
			fail := errors.New("injected failure")
			switch failure {
			case "rename":
				ops.rename = func(string, string) error { return fail }
			case "file-fsync":
				ops.syncFile = func(*os.File) error { return fail }
			case "dir-fsync":
				ops.syncDir = func(*os.File) error { return fail }
			case "crash":
				ops.rename = func(string, string) error { panic("simulated crash after durable write") }
			}
			var err error
			func() {
				defer func() {
					if p := recover(); p != nil && failure != "crash" {
						panic(p)
					}
				}()
				err = replaceServiceTokenFileWithOps(path, old, next, ops)
			}()
			if failure != "crash" && err == nil {
				t.Fatal("failure lost")
			}
			if err != nil && strings.Contains(err.Error(), next) {
				t.Fatal("credential in error")
			}
			recovery := path
			if failure != "dir-fsync" {
				files, _ := filepath.Glob(filepath.Join(filepath.Dir(path), ".service-token-*"))
				if len(files) != 1 {
					t.Fatal("recovery file missing")
				}
				recovery = files[0]
				current, e := ReadServiceTokenFile(path)
				if e != nil || current != old {
					t.Fatal("predecessor changed")
				}
			}
			actual, e := ReadServiceTokenFile(recovery)
			if e != nil || actual != next {
				t.Fatal("recovery credential missing", e)
			}
			if err != nil && !strings.Contains(err.Error(), recovery) {
				t.Fatal("recovery path not reported")
			}
		})
	}
}

type rotationTransport func(*http.Request) (*http.Response, error)

func (f rotationTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestServiceTokenRotationProtocolWithoutSockets(t *testing.T) {
	for _, failure := range []string{"none", "rename", "file-fsync", "dir-fsync", "confirmation", "disconnect"} {
		t.Run(failure, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			old := "cst_" + strings.Repeat("a", 64)
			next := "cst_" + strings.Repeat("b", 64)
			if err := os.WriteFile(path, []byte(old), 0600); err != nil {
				t.Fatal(err)
			}
			base, _ := url.Parse("https://hub.example.com")
			rotated, confirmed := 0, 0
			transport := rotationTransport(func(r *http.Request) (*http.Response, error) {
				response := func(body any) (*http.Response, error) {
					raw, _ := json.Marshal(body)
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
				}
				switch r.URL.Path {
				case "/v1/operator/service-tokens/rotate":
					if r.Header.Get("Authorization") != "Bearer "+old {
						t.Fatal("unexpected rotate credential")
					}
					rotated++
					if failure == "disconnect" && rotated == 1 {
						return nil, io.ErrUnexpectedEOF
					}
					return response(map[string]string{"token": next})
				case "/v1/operator/service-tokens/self":
					if r.Header.Get("Authorization") == "Bearer "+next {
						actual, err := ReadServiceTokenFile(path)
						if err != nil || actual != next {
							t.Fatal("confirmed before installation")
						}
						confirmed++
						if failure == "confirmation" {
							return nil, io.ErrUnexpectedEOF
						}
					} else if r.Header.Get("Authorization") != "Bearer "+old {
						t.Fatal("unexpected self credential")
					}
					return response(ServiceTokenSelf{ID: "metadata-id", ExpiresAt: time.Now().Add(time.Hour)})
				}
				return nil, errors.New("unexpected route")
			})
			client := &Client{base: base, token: old, http: &http.Client{Transport: transport}}
			ops := defaultTokenFileOps()
			switch failure {
			case "rename":
				ops.rename = func(string, string) error { return errors.New("rename failure") }
			case "file-fsync":
				ops.syncFile = func(*os.File) error { return errors.New("sync failure") }
			case "dir-fsync":
				ops.syncDir = func(*os.File) error { return errors.New("sync failure") }
			}
			changed, err := client.rotateTokenFileWithOps(context.Background(), path, 14*24*time.Hour, false, ops)
			if failure == "none" {
				if err != nil || !changed || confirmed != 1 {
					t.Fatal("rotation not confirmed", err)
				}
			} else {
				if err == nil || changed {
					t.Fatal("failure reported complete")
				}
				if strings.Contains(err.Error(), next) {
					t.Fatal("credential in error")
				}
				if failure != "confirmation" && confirmed != 0 {
					t.Fatal("failed installation consumed successor")
				}
			}
			if failure == "disconnect" {
				actual, e := ReadServiceTokenFile(path)
				if e != nil || actual != old {
					t.Fatal("lost response changed file")
				}
				if changed, err = client.RotateTokenFile(context.Background(), path, 14*24*time.Hour, false); err != nil || !changed || rotated != 2 || confirmed != 1 {
					t.Fatal("retry after disconnect", err)
				}
			}
		})
	}
}
