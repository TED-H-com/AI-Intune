package store

import (
	"github.com/teddashh/AI-Intune/internal/totp"
	"testing"
	"time"
)

func TestSessionMFAProofLifecycle(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	old, err := s.CreateSession(a, "192.0.2.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, now.Unix()/30)
	if _, err = s.ConfirmTOTPForSession(a.AccountID, code, old); err != nil {
		t.Fatal(err)
	}
	got, err := s.LookupSession(old)
	if err != nil || !got.SessionMFAVerifiedAt.Equal(now) {
		t.Fatal("enrollment proof missing", err)
	}
	now = now.Add(time.Minute)
	a, err = s.VerifyPassword("admin", testAdminPassword, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	code, _ = totp.Code(secret, now.Unix()/30)
	if err = s.VerifyLoginSecondFactor(a, "192.0.2.1", code); err != nil {
		t.Fatal(err)
	}
	session, err := s.CreateSession(a, "192.0.2.1", "test", true)
	if err != nil {
		t.Fatal(err)
	}
	got, err = s.LookupSession(session)
	if err != nil || !got.SessionMFAVerifiedAt.Equal(now) {
		t.Fatal("login proof missing", err)
	}
	now = now.Add(time.Hour)
	if err = s.RefreshSessionMFA(session, a.AccountID); err != nil {
		t.Fatal(err)
	}
	got, err = s.LookupSession(session)
	if err != nil || !got.SessionMFAVerifiedAt.Equal(now) {
		t.Fatal("refresh missing", err)
	}
	if err = s.RevokeSession(session); err != nil {
		t.Fatal(err)
	}
	if err = s.RefreshSessionMFA(session, a.AccountID); err == nil {
		t.Fatal("revoked session revived")
	}
}
