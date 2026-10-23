package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

func runSecretsPull(args []string) {
	fs := flag.NewFlagSet("secrets-pull", flag.ExitOnError)
	configPath := fs.String("config", os.Getenv("CLAWCTL_SECRETS_CONFIG"), "Reference-only secrets configuration")
	ref := fs.String("ref", "", "Configured secret reference")
	output := fs.String("output", "", "Absolute destination in a private directory")
	_ = fs.Parse(args)
	if e := pullSecret(context.Background(), *configPath, *ref, *output); e != nil {
		log.Fatal("secret pull failed")
	}
}
func pullSecret(ctx context.Context, configPath, ref, output string) error {
	r, e := secrets.LoadConfig(configPath, nil)
	if e != nil {
		return e
	}
	refs, e := r.List(ctx, "")
	if e != nil {
		return e
	}
	allowed := false
	for _, candidate := range refs {
		if candidate.Ref == ref {
			allowed = true
			break
		}
	}
	if !allowed {
		return errors.New("secret reference not configured")
	}
	// Only configured metadata enters the audit log, never values or backend errors.
	log.Printf("secret pull requested uid=%d ref=%q", os.Getuid(), ref)
	e = writePulledSecret(ctx, r, ref, output)
	log.Printf("secret pull completed uid=%d ref=%q ok=%t", os.Getuid(), ref, e == nil)
	return e
}
func writePulledSecret(ctx context.Context, r secrets.SecretProvider, ref, output string) error {
	if !filepath.IsAbs(output) {
		return errors.New("absolute secret destination required")
	}
	dir := filepath.Dir(output)
	if e := os.MkdirAll(dir, 0700); e != nil {
		return errors.New("secret destination unavailable")
	}
	info, e := os.Lstat(dir)
	if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private secret directory required")
	}
	value, e := r.Get(ctx, ref)
	if e != nil {
		return errors.New("secret unavailable")
	}
	f, e := os.CreateTemp(dir, ".secret-*")
	if e != nil {
		return errors.New("secret destination unavailable")
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(0600); e == nil {
		_, e = f.WriteString(value.Reveal())
	}
	if e == nil {
		e = f.Sync()
	}
	closeErr := f.Close()
	if e != nil || closeErr != nil {
		return errors.New("secret write failed")
	}
	if os.Rename(f.Name(), output) != nil {
		return errors.New("secret write failed")
	}
	return nil
}
