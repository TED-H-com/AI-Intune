package secrets

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSecretRedaction(t *testing.T) {
	const sentinel = "sentinel-secret-123"
	secret := NewSecret(sentinel)
	data, err := json.Marshal(struct{ Value Secret }{secret})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	log.New(&logs, "", 0).Printf("%v %+v %#v %s %q %x", secret, secret, secret, secret, secret, secret)
	for _, out := range []string{secret.String(), secret.GoString(), string(data), logs.String(), fmt.Sprintf("%+v", &secret)} {
		if strings.Contains(out, sentinel) {
			t.Fatal("secret escaped redaction")
		}
	}
	if secret.Reveal() != sentinel {
		t.Fatal("explicit reveal failed")
	}
}
func TestProviders(t *testing.T) {
	ctx := context.Background()
	t.Setenv("SECRET_TEST", "value")
	path := filepath.Join(t.TempDir(), "with # space.env")
	if err := os.WriteFile(path, []byte("\ufeffexport TOKEN='value'\r\nEMPTY=\nTOKEN=\"rotated\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	refs := []Reference{{"env", "env://SECRET_TEST"}, {"file", FileReference(path, "TOKEN")}}
	r := New(refs)
	for _, tc := range []struct{ ref, want string }{{refs[0].Ref, "value"}, {refs[1].Ref, "rotated"}} {
		got, err := r.Get(ctx, tc.ref)
		if err != nil || got.Reveal() != tc.want {
			t.Fatalf("provider resolution failed: %v", err)
		}
	}
	for _, ref := range []string{FileReference(path, "EMPTY"), FileReference(path, "ABSENT"), "env://SECRET_TEST_ABSENT"} {
		if _, err := r.Get(ctx, ref); !errors.Is(err, ErrMissing) {
			t.Fatalf("want missing: %v", err)
		}
	}
	if _, err := r.Get(ctx, "bws://project/key"); !errors.Is(err, ErrNotConfigured) {
		t.Fatal(err)
	}
	if !errors.Is(r.Health(ctx), ErrNotConfigured) {
		t.Fatal("bws health")
	}
	for _, ref := range []string{"file://host/tmp/a#KEY", "file:relative#KEY", "env://SECRET_TEST/path", "unknown://key", "%"} {
		if _, err := r.Get(ctx, ref); err == nil {
			t.Fatal("accepted invalid reference")
		}
	}
	listed, err := r.List(ctx, "file:")
	if err != nil || len(listed) != 1 {
		t.Fatal("scope listing")
	}
	if err := os.WriteFile(path, []byte("TOKEN=new\n"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := r.Get(ctx, refs[1].Ref)
	if err != nil || got.Reveal() != "new" {
		t.Fatal("rotation")
	}
}

func TestFileSnapshotDoesNotMixRotations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notify.env")
	if err := os.WriteFile(path, []byte("TELEGRAM_BOT_TOKEN=before\nTELEGRAM_CHAT_ID=before\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider, mode, err := NewFileSnapshot(path)
	if err != nil || mode != 0600 {
		t.Fatal("snapshot load failed")
	}
	if err := os.WriteFile(path, []byte("TELEGRAM_BOT_TOKEN=after\nTELEGRAM_CHAT_ID=after\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, key := range NotifyKeys[:2] {
		value, err := provider.Get(context.Background(), FileReference(path, key))
		if err != nil || value.Reveal() != "before" {
			t.Fatal("snapshot mixed rotations")
		}
	}
}
