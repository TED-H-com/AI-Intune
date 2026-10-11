package store

import (
	"errors"
	"testing"
	"time"
)

func TestServiceTokenRotationChain(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	actor, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := s.now().UTC()
	s.nowFn = func() time.Time { return now }
	old, secret, err := s.CreateServiceToken(ServiceToken{Name: "hermes", Scope: "view", ExpiresAt: now.Add(30 * 24 * time.Hour), Allowlist: []string{"GET /v1/operator/jobs"}, SourceCIDRs: []string{"192.0.2.0/24"}, MaxLifetimeSeconds: 180 * 86400}, actor.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * 24 * time.Hour)
	next, newSecret, err := s.RotateServiceToken(old.ID, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if next.Name != old.Name || next.RotatedFrom != old.ID || next.RotationChainID != old.ID || next.ExpiresAt.Sub(now) != 30*24*time.Hour {
		t.Fatal("rotation changed contract")
	}
	if _, _, err = s.RotateServiceToken(old.ID, "192.0.2.1"); !errors.Is(err, ErrServiceTokenRotated) {
		t.Fatal(err)
	}
	for _, value := range []string{secret, newSecret} {
		if _, err = s.AuthenticateServiceToken(value, "POST /v1/operator/service-tokens/rotate", "192.0.2.1", "view"); err != nil {
			t.Fatal(err)
		}
		if _, err = s.AuthenticateServiceToken(value, "POST /v1/operator/service-tokens/rotate", "198.51.100.1", "view"); err == nil {
			t.Fatal("CIDR bypass")
		}
	}
	now = now.Add(10 * time.Minute)
	if _, err = s.AuthenticateServiceToken(secret, "GET /v1/operator/jobs", "192.0.2.1", "view"); err == nil {
		t.Fatal("overlap accepted at deadline")
	}
	if err = s.RevokeServiceToken(old.ID, actor.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.AuthenticateServiceToken(newSecret, "GET /v1/operator/jobs", "192.0.2.1", "view"); err == nil {
		t.Fatal("chain not revoked")
	}
	if _, _, err = s.RotateServiceToken(next.ID, "192.0.2.1"); err == nil {
		t.Fatal("revoked rotated")
	}
	rows, err := s.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range rows {
		if a.Action == "service-token-rotate" {
			found = true
			if a.Subject != old.ID || a.Detail != "rotated to "+next.ID || a.AuthSubject != "service:hermes" {
				t.Fatal("audit mismatch")
			}
		}
	}
	if !found {
		t.Fatal("missing rotation audit")
	}
}

func TestServiceTokenRotationLimits(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	actor, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	now := s.now().UTC()
	s.nowFn = func() time.Time { return now }
	create := func(name string) ServiceToken {
		token, _, e := s.CreateServiceToken(ServiceToken{Name: name, Scope: "view", ExpiresAt: now.Add(90 * 24 * time.Hour), Allowlist: []string{"GET /v1/operator/jobs"}, MaxLifetimeSeconds: 180 * 86400}, actor.AccountID)
		if e != nil {
			t.Fatal(e)
		}
		return token
	}
	expired := create("expired")
	limited := create("limited")
	now = now.Add(90 * 24 * time.Hour)
	if _, _, err = s.RotateServiceToken(expired.ID, "192.0.2.1"); err == nil {
		t.Fatal("expired rotated")
	}
	// Move back just inside expiry, then advance close to the chain limit.
	now = now.Add(-time.Hour)
	limited, _, err = s.RotateServiceToken(limited.ID, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	now = limited.ExpiresAt.Add(-time.Minute)
	limited, _, err = s.RotateServiceToken(limited.ID, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if max := limited.MaxExpiry(); max == nil || !limited.ExpiresAt.Equal(*max) {
		t.Fatal("expiry not clamped")
	}
	now = limited.ExpiresAt
	if _, _, err = s.RotateServiceToken(limited.ID, "192.0.2.1"); err == nil {
		t.Fatal("maximum lifetime exceeded")
	}
	now = now.Add(time.Hour)
	for i, name := range []string{"a", "b", "c", "d"} {
		token := create(name)
		_, _, err = s.RotateServiceToken(token.ID, "192.0.2.2")
		if i < 3 && err != nil {
			t.Fatal(err)
		}
		if i == 3 && !errors.Is(err, ErrServiceTokenRateLimit) {
			t.Fatal("rate limit", err)
		}
	}
}
