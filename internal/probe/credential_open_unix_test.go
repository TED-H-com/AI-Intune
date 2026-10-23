//go:build unix

package probe

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"golang.org/x/sys/unix"
)

func TestPrivateCredentialReplacementRace(t *testing.T) {
	for _, kind := range []string{"symlink", "fifo", "mode", "oversize"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "oauth-token")
			if err := os.WriteFile(path, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			target := path + ".target"
			secret := "synthetic-private-token"
			if err := os.WriteFile(target, []byte(secret), 0600); err != nil {
				t.Fatal(err)
			}
			// Replace after Lstat but immediately before the real safe open.
			opener := func(p string) (*os.File, error) {
				if err := os.Remove(p); err != nil {
					return nil, err
				}
				var err error
				switch kind {
				case "symlink":
					err = os.Symlink(target, p)
				case "fifo":
					err = unix.Mkfifo(p, 0600)
				case "mode":
					err = os.WriteFile(p, []byte(secret), 0644)
				case "oversize":
					err = os.WriteFile(p, []byte(strings.Repeat("x", 64*1024+1)), 0600)
				}
				if err != nil {
					return nil, err
				}
				return openPrivateCredential(p)
			}
			type result struct {
				b       []byte
				c       model.Credential
				present bool
			}
			done := make(chan result, 1)
			go func() {
				b, c, present := privateCredentialWithOpener("claude", "claude-automation", path, true, opener)
				done <- result{b, c, present}
			}()
			select {
			case r := <-done:
				if r.b != nil || !r.present || r.c.Status != model.CredFailed || r.c.Note == "" {
					t.Fatalf("unsafe result: %+v", r.c)
				}
				reported, _ := json.Marshal(r.c)
				if strings.Contains(string(reported), secret) {
					t.Fatal("secret leaked")
				}
				if kind == "fifo" && r.c.Note != "credential file is not a regular file" {
					t.Fatalf("FIFO reason: %s", r.c.Note)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("credential inspection blocked on replacement")
			}
		})
	}
}

func TestPrivateCredentialFIFOIsPrompt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "oauth-token")
	if err := unix.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan model.Credential, 1)
	go func() { _, c, _ := privateCredential("claude", "claude-automation", path, true); done <- c }()
	select {
	case c := <-done:
		if c.Status != model.CredFailed || c.Note != "credential file is not a regular file" {
			t.Fatalf("FIFO: %+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("FIFO inspection blocked")
	}
}
