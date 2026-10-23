package store

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestHubLoginUnderWriterLoad(t *testing.T) {
	fastAccountHashes(t)
	for _, kind := range []string{"wrong", "unknown", "locked", "success"} {
		t.Run(kind, func(t *testing.T) {
			s := newTestStore(t)
			if _, err := s.CreateFirstAdmin("admin", testAdminPassword); err != nil {
				t.Fatal(err)
			}
			if kind == "locked" {
				for range 5 {
					if _, err := s.VerifyPassword("admin", "wrong", "192.0.2.1"); !errors.Is(err, ErrAccountAuth) {
						t.Fatal(err)
					}
				}
			}
			// Bulk retains its 15s budget. The old VerifyPassword waited on this
			// held writer; rejected attempts must fall back and persist after release.
			s.SetInteractiveWriterWait(100 * time.Millisecond)
			held, err := s.beginWrite(context.Background(), "long_bulk")
			if err != nil {
				t.Fatal(err)
			}
			defer held.Rollback()
			user, password := "admin", "wrong"
			if kind == "unknown" {
				user = "unknown"
			}
			if kind == "locked" || kind == "success" {
				password = testAdminPassword
			}
			done := make(chan error, 1)
			start := time.Now()
			go func() { _, err := s.VerifyPassword(user, password, "192.0.2.1"); done <- err }()
			if kind != "success" {
				waitWriterQueue(t, s, 1, 0)
				if err := held.Rollback(); err != nil {
					t.Fatal(err)
				}
			}
			select {
			case err := <-done:
				if kind == "success" {
					if !IsBusy(err) {
						t.Fatalf("success must fail closed: %v", err)
					}
				} else if !errors.Is(err, ErrAccountAuth) {
					t.Fatalf("rejection: %v", err)
				}
				if elapsed := time.Since(start); elapsed >= 500*time.Millisecond {
					t.Fatalf("login took %s", elapsed)
				}
			case <-time.After(2 * time.Second):
				held.Rollback()
				<-done
				t.Fatal("login waited on held bulk writer")
			}
		})
	}
}

func TestHubLoginRechecksQueuedDurableState(t *testing.T) {
	fastAccountHashes(t)
	for _, change := range []string{
		`UPDATE hub_accounts SET password_hash='reset'`,
		`UPDATE hub_accounts SET auth_generation=auth_generation+1`,
		`UPDATE hub_accounts SET disabled_at='2026-01-01T00:00:00Z'`,
		`INSERT INTO hub_login_failures(account_id,client_ip,failed_attempts,locked_until,last_failed_at) SELECT account_id,'192.0.2.1',5,'2099-01-01T00:00:00Z','2099-01-01T00:00:00Z' FROM hub_accounts`,
	} {
		t.Run(change, func(t *testing.T) {
			s := newTestStore(t)
			if _, err := s.CreateFirstAdmin("admin", testAdminPassword); err != nil {
				t.Fatal(err)
			}
			s.SetInteractiveWriterWait(2 * time.Second)
			held, err := s.beginWrite(context.Background(), "concurrent_change")
			if err != nil {
				t.Fatal(err)
			}
			defer held.Rollback()
			done := make(chan error, 1)
			go func() { _, err := s.VerifyPassword("admin", testAdminPassword, "192.0.2.1"); done <- err }()
			waitWriterQueue(t, s, 0, 1) // Reader snapshot and argon have completed.
			if _, err := held.Exec(change); err != nil {
				t.Fatal(err)
			}
			if err := held.Commit(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; !errors.Is(err, ErrAccountAuth) {
				t.Fatalf("concurrent change did not win: %v", err)
			}
		})
	}
}

func TestRejectedLoginBulkFallbackLocksAndAudits(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	s.SetInteractiveWriterWait(20 * time.Millisecond)
	held, err := s.beginWrite(context.Background(), "held")
	if err != nil {
		t.Fatal(err)
	}
	defer held.Rollback()
	done := make(chan error, 5)
	for range 5 {
		go func() { _, err := s.VerifyPassword("admin", "wrong", "192.0.2.1"); done <- err }()
	}
	waitWriterQueue(t, s, 5, 0)
	if err := held.Rollback(); err != nil {
		t.Fatal(err)
	}
	for range 5 {
		if err := <-done; !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
	}
	var failed int
	var locked string
	if err := s.rdb.QueryRow("SELECT failed_attempts,locked_until FROM hub_login_failures WHERE account_id=?", a.AccountID).Scan(&failed, &locked); err != nil {
		t.Fatal(err)
	}
	if failed != 5 || locked == "" {
		t.Fatalf("failed=%d locked=%q", failed, locked)
	}
	var audits int
	if err := s.rdb.QueryRow("SELECT COUNT(*) FROM audit_log WHERE action=?", AuditHubLoginFailed).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	if audits != 5 {
		t.Fatalf("failed audit rows=%d", audits)
	}
	if _, err := s.VerifyPassword("admin", testAdminPassword, "192.0.2.1"); !errors.Is(err, ErrAccountAuth) {
		t.Fatal(err)
	}
}
