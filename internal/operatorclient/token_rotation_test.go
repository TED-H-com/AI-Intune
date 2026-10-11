package operatorclient

import (
	"context"
	"encoding/json"
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
	if len(files) != 0 {
		t.Fatal("temporary files left")
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
		if r.Header.Get("Authorization") != "Bearer "+old {
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
