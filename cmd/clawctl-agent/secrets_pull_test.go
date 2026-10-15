package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

func TestSecretPullPrivateAtomicDestination(t *testing.T) {
	t.Setenv("PULL_TEST_VALUE", "pull-value")
	dir := filepath.Join(t.TempDir(), "private")
	output := filepath.Join(dir, "value")
	if e := writePulledSecret(context.Background(), secrets.New(nil), "env://PULL_TEST_VALUE", output); e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(output)
	if e != nil || string(raw) != "pull-value" {
		t.Fatal("pull failed")
	}
	for path, want := range map[string]os.FileMode{dir: 0700, output: 0600} {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != want {
			t.Fatal("permissions")
		}
	}
	if e := os.Chmod(output, 0644); e != nil {
		t.Fatal(e)
	}
	if e := writePulledSecret(context.Background(), secrets.New(nil), "env://PULL_TEST_VALUE", output); e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(output)
	if info.Mode().Perm() != 0600 {
		t.Fatal("replacement not private")
	}
	if e := os.Chmod(dir, 0755); e != nil {
		t.Fatal(e)
	}
	if e := writePulledSecret(context.Background(), secrets.New(nil), "env://PULL_TEST_VALUE", output); e == nil {
		t.Fatal("public directory accepted")
	}
	if e := pullSecret(context.Background(), "", "env://PULL_TEST_VALUE", output); e == nil {
		t.Fatal("unconfigured reference accepted")
	}
}
