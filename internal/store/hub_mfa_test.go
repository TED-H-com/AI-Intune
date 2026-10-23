package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/totp"
)

func TestMFALifecycleReplayRecoveryLockout(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, now.Unix()/30)
	codes, err := s.ConfirmTOTP(a.AccountID, code)
	if err != nil || len(codes) != 10 {
		t.Fatal(codes, err)
	}
	if _, err = s.BeginTOTPEnrollment(a.AccountID); err == nil {
		t.Fatal("replaced enabled factor")
	}
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", code); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("enrollment code replay", err)
	}
	now = now.Add(30 * time.Second)
	code, _ = totp.Code(secret, now.Unix()/30)
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", code); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", code); err == nil {
		t.Fatal("replayed code")
	}
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", codes[0]); err != nil {
		t.Fatal(err)
	}
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", codes[0]); err == nil {
		t.Fatal("reused recovery")
	}
	for range 4 {
		if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", "bad"); err == nil {
			t.Fatal("bad code")
		}
	}
	if _, err = s.VerifyPassword("admin", testAdminPassword, "192.0.2.1"); err == nil {
		t.Fatal("password bypassed second-factor lockout")
	}
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", codes[1]); err == nil {
		t.Fatal("recovery bypassed lockout")
	}
	now = now.Add(16 * time.Minute)
	if err = s.VerifySecondFactor(a.AccountID, "192.0.2.1", codes[1]); err != nil {
		t.Fatal(err)
	}

	if err = s.DisableMFA(a.AccountID); err != nil {
		t.Fatal(err)
	}
	enabled, err := s.MFAEnabled(a.AccountID)
	if enabled || err != nil {
		t.Fatal(enabled, err)
	}
	rows, err := s.rdb.Query(`SELECT * FROM audit_log`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]bool{}
	for rows.Next() {
		values := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range values {
			dest[i] = &values[i]
		}
		if err = rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		for i, value := range values {
			text := fmt.Sprint(value)
			if columns[i] == "action" {
				actions[text] = true
			}
			if strings.Contains(text, secret) {
				t.Fatal("audit secret")
			}
			for _, c := range codes {
				if strings.Contains(text, c) {
					t.Fatal("audit code")
				}
			}
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	for _, action := range []AuditAction{AuditMFAEnabled, AuditMFADisabled, AuditMFAFailed, AuditRecoveryCodeUsed} {
		if !actions[string(action)] {
			t.Fatal("missing MFA audit", action)
		}
	}
}

func TestMFAConcurrentConsumption(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	secret, _ := s.BeginTOTPEnrollment(a.AccountID)
	code, _ := totp.Code(secret, now.Unix()/30-1)
	codes, err := s.ConfirmTOTP(a.AccountID, code)
	if err != nil {
		t.Fatal(err)
	}
	code, _ = totp.Code(secret, now.Unix()/30)
	for _, value := range []string{code, codes[0]} {
		results := make(chan error, 2)
		for range 2 {
			go func() { results <- s.VerifySecondFactor(a.AccountID, "192.0.2.1", value) }()
		}
		wins := 0
		for range 2 {
			if err := <-results; err == nil {
				wins++
			} else if !errors.Is(err, ErrAccountAuth) {
				t.Fatal(err)
			}
		}
		if wins != 1 {
			t.Fatal("concurrent consumption", wins)
		}
	}
}

func TestMFAClientLockoutSharedWithPassword(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, now.Unix()/30)
	codes, err := s.ConfirmTOTP(a.AccountID, code)
	if err != nil {
		t.Fatal(err)
	}
	ip := "2001:db8:1:2::1"
	for range 2 {
		if _, err = s.VerifyPassword("admin", "wrong", ip); !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
	}
	// Password success while MFA is enabled must not clear the pair's counter.
	if _, err = s.VerifyPassword("admin", testAdminPassword, ip); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		rotating := fmt.Sprintf("2001:db8:1:2::%x", i+2)
		if err = s.VerifySecondFactor(a.AccountID, rotating, "bad"); !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
	}
	var failed, legacy int
	var locked string
	if err = s.rdb.QueryRow(`SELECT failed_attempts,locked_until FROM hub_login_failures WHERE account_id=? AND client_ip=?`, a.AccountID, "2001:db8:1:2::/64").Scan(&failed, &locked); err != nil || failed != 5 || locked != fmtTime(now.Add(15*time.Minute)) {
		t.Fatal(failed, locked, err)
	}
	if err = s.rdb.QueryRow(`SELECT failed_attempts FROM hub_accounts WHERE account_id=?`, a.AccountID).Scan(&legacy); err != nil || legacy != 0 {
		t.Fatal("global counter changed", legacy, err)
	}
	if err = s.VerifySecondFactor(a.AccountID, "2001:db8:1:2::ffff", codes[0]); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("same /64 bypassed lock", err)
	}
	if _, err = s.VerifyPassword("admin", testAdminPassword, ip); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("password bypassed shared lock", err)
	}
	// A different /64 still completes both factors, without clearing the locked pair.
	other := "2001:db8:1:3::1"
	if _, err = s.VerifyPassword("admin", testAdminPassword, other); err != nil {
		t.Fatal(err)
	}
	now = now.Add(30 * time.Second)
	code, _ = totp.Code(secret, now.Unix()/30)
	if err = s.VerifySecondFactor(a.AccountID, other, code); err != nil {
		t.Fatal("other IP TOTP blocked", err)
	}
	if err = s.VerifySecondFactor(a.AccountID, ip, codes[0]); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("other IP cleared lock", err)
	}
	now = now.Add(15 * time.Minute)
	if err = s.VerifySecondFactor(a.AccountID, ip, codes[0]); err != nil {
		t.Fatal("lock did not expire or consumed rejected recovery code", err)
	}
	var rows int
	if err = s.rdb.QueryRow(`SELECT count(*) FROM hub_login_failures WHERE account_id=?`, a.AccountID).Scan(&rows); err != nil || rows != 0 {
		t.Fatal(rows, err)
	}
}

func TestMFAFailuresFeedDistributedGuessingSignal(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, now.Unix()/30)
	codes, err := s.ConfirmTOTP(a.AccountID, code)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 25 {
		ip := fmt.Sprintf("192.0.2.%d", i+1)
		if _, err = s.VerifyPassword("admin", "wrong", ip, AuditEntry{SourceAddr: ip}); !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
	}
	for i := range 26 {
		ip := fmt.Sprintf("198.51.100.%d", i+1)
		if err = s.VerifySecondFactor(a.AccountID, ip, "bad", AuditEntry{SourceAddr: ip}); !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
		var signals int
		if err = s.rdb.QueryRow(`SELECT count(*) FROM audit_log WHERE action=? AND auth_subject=?`, AuditHubGuessing, "local-user:"+a.AccountID).Scan(&signals); err != nil {
			t.Fatal(err)
		}
		want := 0
		if i >= 24 {
			want = 1
		}
		if signals != want {
			t.Fatalf("second-factor failures=%d signals=%d want=%d", i+1, signals, want)
		}
	}
	if err = s.VerifySecondFactor(a.AccountID, "203.0.113.1", codes[0]); err != nil {
		t.Fatal("distributed guessing globally locked account", err)
	}
	now = now.Add(61 * time.Minute)
	for i := range 50 {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		if err = s.VerifySecondFactor(a.AccountID, ip, "bad", AuditEntry{SourceAddr: ip}); !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
	}
	var signals int
	if err = s.rdb.QueryRow(`SELECT count(*) FROM audit_log WHERE action=?`, AuditHubGuessing).Scan(&signals); err != nil || signals != 2 {
		t.Fatal(signals, err)
	}
}

func TestEnrollmentRevokesPasswordOnlySessionsAndLogins(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	current, err := s.CreateSession(a, "192.0.2.1", "")
	if err != nil {
		t.Fatal(err)
	}
	other, err := s.CreateSession(a, "192.0.2.2", "")
	if err != nil {
		t.Fatal(err)
	}
	inFlight, err := s.VerifyPassword("admin", testAdminPassword, "192.0.2.2")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, s.nowFn().Unix()/30)
	if _, err = s.ConfirmTOTPForSession(a.AccountID, code, current); err != nil {
		t.Fatal(err)
	}
	if _, err = s.LookupSession(current); err != nil {
		t.Fatal("enrolling session revoked", err)
	}
	if _, err = s.LookupSession(other); !errors.Is(err, ErrSessionAuth) {
		t.Fatal("password-only session survived", err)
	}
	if _, err = s.CreateSession(inFlight, "192.0.2.2", ""); !errors.Is(err, ErrSessionAuth) {
		t.Fatal("in-flight password login gained session", err)
	}
	fresh, err := s.VerifyPassword("admin", testAdminPassword, "192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSession(fresh, "192.0.2.1", ""); err != nil {
		t.Fatal("current factor snapshot rejected", err)
	}
	// A pending login for an old factor must also fail after host recovery.
	if err = s.DisableMFA(a.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, err = s.CreateSession(fresh, "192.0.2.1", ""); !errors.Is(err, ErrSessionAuth) {
		t.Fatal("stale factor snapshot accepted", err)
	}
}

func TestRegenerateRecoveryCodes(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegenerateAdminRecoveryCodes("admin"); !errors.Is(err, ErrAccountAuth) {
		t.Fatal(err)
	}
	if _, err := s.RegenerateAdminRecoveryCodes("unknown"); err == nil {
		t.Fatal("unknown user accepted")
	}
	secret, _ := s.BeginTOTPEnrollment(a.AccountID)
	code, _ := totp.Code(secret, now.Unix()/30)
	old, err := s.ConfirmTOTP(a.AccountID, code)
	if err != nil {
		t.Fatal(err)
	}
	ip := "192.0.2.1"
	for _, bad := range []string{code, old[0], "bad", "bad", "bad"} {
		if _, err := s.RegenerateRecoveryCodes(a.AccountID, ip, bad); !errors.Is(err, ErrAccountAuth) {
			t.Fatal(err)
		}
	}
	now = now.Add(30 * time.Second)
	code, _ = totp.Code(secret, now.Unix()/30)
	if _, err := s.RegenerateRecoveryCodes(a.AccountID, ip, code); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("lockout bypass", err)
	}
	var count int
	if err := s.DB().QueryRow(`SELECT count(*) FROM hub_account_recovery_codes WHERE account_id=? AND used_at IS NULL`, a.AccountID).Scan(&count); err != nil || count != 10 {
		t.Fatal(count, err)
	}
	// Recovery rejection neither consumes the code nor changes the set.
	if err := s.VerifySecondFactor(a.AccountID, "192.0.2.2", old[0]); err != nil {
		t.Fatal(err)
	}
	now = now.Add(16 * time.Minute)
	code, _ = totp.Code(secret, now.Unix()/30)
	if _, err := s.DB().Exec(`UPDATE hub_accounts SET disabled_at=? WHERE account_id=?`, fmtTime(now), a.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RegenerateRecoveryCodes(a.AccountID, ip, code); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("disabled account accepted", err)
	}
	if _, err := s.DB().Exec(`UPDATE hub_accounts SET disabled_at=NULL WHERE account_id=?`, a.AccountID); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.RegenerateRecoveryCodes(a.AccountID, ip, code)
	if err != nil || len(fresh) != 10 {
		t.Fatal("regeneration failed", err)
	}
	seen := map[string]bool{}
	for _, c := range fresh {
		if seen[c] {
			t.Fatal("duplicate")
		}
		seen[c] = true
	}
	if _, err := s.RegenerateRecoveryCodes(a.AccountID, ip, code); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("replay", err)
	}
	for i, c := range old {
		if err := s.VerifySecondFactor(a.AccountID, fmt.Sprintf("198.51.100.%d", i+1), c); !errors.Is(err, ErrAccountAuth) {
			t.Fatal("old code accepted", err)
		}
	}
	for _, c := range fresh {
		if err := s.VerifySecondFactor(a.AccountID, ip, c); err != nil {
			t.Fatal(err)
		}
		if err := s.VerifySecondFactor(a.AccountID, ip, c); !errors.Is(err, ErrAccountAuth) {
			t.Fatal("reuse", err)
		}
	}
	if !IsKnownAuditAction(AuditRecoveryCodesRegenerated) {
		t.Fatal("unknown regeneration audit action")
	}
	rows, err := s.DB().Query(`SELECT * FROM audit_log WHERE action=?`, AuditRecoveryCodesRegenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, _ := rows.Columns()
	if !rows.Next() {
		t.Fatal("missing audit")
	}
	values := make([]any, len(columns))
	dest := make([]any, len(columns))
	for i := range values {
		dest[i] = &values[i]
	}
	if err := rows.Scan(dest...); err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		for _, c := range append(old, fresh...) {
			if strings.Contains(fmt.Sprint(value), c) {
				t.Fatal("audit contains code")
			}
		}
	}
}

func TestMFAAccountLockAcrossClientKeys(t *testing.T) {
	fastAccountHashes(t)
	s := newTestStore(t)
	now := time.Unix(1800000000, 0)
	s.nowFn = func() time.Time { return now }
	a, err := s.CreateFirstAdmin("admin", testAdminPassword)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := s.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := totp.Code(secret, now.Unix()/30)
	codes, err := s.ConfirmTOTP(a.AccountID, code)
	if err != nil {
		t.Fatal(err)
	}
	keys := 0
	freshKey := func() string {
		keys++
		return fmt.Sprintf("2001:db8:%x::1", keys)
	}
	// A six-digit code outside the accepted skew window: indistinguishable in
	// shape from a real guess, but never valid.
	wrong := func() string {
		valid := map[string]bool{}
		for d := int64(-1); d <= 1; d++ {
			c, _ := totp.Code(secret, now.Unix()/30+d)
			valid[c] = true
		}
		for n := 0; ; n++ {
			if c := fmt.Sprintf("%06d", n); !valid[c] {
				return c
			}
		}
	}
	fail := func(n int, key func() string) {
		t.Helper()
		for range n {
			if err := s.VerifySecondFactor(a.AccountID, key(), wrong()); !errors.Is(err, ErrAccountAuth) {
				t.Fatal(err)
			}
		}
	}
	nextCode := func() string {
		now = now.Add(30 * time.Second)
		c, _ := totp.Code(secret, now.Unix()/30)
		return c
	}
	accountRow := func() (failed int, locked sql.NullString, ok bool) {
		t.Helper()
		err := s.rdb.QueryRow(`SELECT failed_attempts,locked_until FROM hub_mfa_failures WHERE account_id=?`, a.AccountID).Scan(&failed, &locked)
		if errors.Is(err, sql.ErrNoRows) {
			return 0, locked, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return failed, locked, true
	}
	lockouts := func() []string {
		t.Helper()
		rows, err := s.rdb.Query(`SELECT detail FROM audit_log WHERE action=? AND auth_subject=? AND detail IS NOT NULL ORDER BY audit_id`, AuditHubLockout, "local-user:"+a.AccountID)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var details []string
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				t.Fatal(err)
			}
			details = append(details, d)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return details
	}
	lockDetail := func(at time.Time) string {
		return "second factor: 10 consecutive failures across client keys; authenticator codes locked until " + fmtTime(at.Add(time.Hour))
	}

	// One below the limit, a valid code from any key still completes and resets the count.
	fail(9, freshKey)
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); err != nil {
		t.Fatal("below the account limit", err)
	}
	if _, _, ok := accountRow(); ok {
		t.Fatal("success kept the account count")
	}

	// The tenth consecutive failure, each from a different /64, locks authenticator codes everywhere.
	fail(10, freshKey)
	lockedAt := now
	if got := lockouts(); len(got) != 1 || got[0] != lockDetail(lockedAt) {
		t.Fatalf("account lockout audit: %q", got)
	}
	locked := nextCode()
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), locked); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("login accepted authenticator code during account lock", err)
	}
	if err = s.VerifyAdminTOTP(a.AccountID, freshKey(), locked); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("step-up accepted authenticator code during account lock", err)
	}
	var last int64
	if err = s.rdb.QueryRow(`SELECT last_used_step FROM hub_account_mfa WHERE account_id=?`, a.AccountID).Scan(&last); err != nil || last >= now.Unix()/30 {
		t.Fatal("refused code consumed its step", last, err)
	}
	// Submissions refused by the lock neither extend nor reset it.
	fail(25, freshKey)
	lockedKey := freshKey()
	fail(5, func() string { return lockedKey })
	var keyFailures int
	if err = s.rdb.QueryRow(`SELECT count(*) FROM hub_login_failures WHERE account_id=? AND client_ip=?`, a.AccountID, lockedKey).Scan(&keyFailures); err != nil || keyFailures != 0 {
		t.Fatal("account-lock refusals consumed the per-key budget", keyFailures, err)
	}
	if failed, until, _ := accountRow(); failed != 10 || until.String != fmtTime(lockedAt.Add(time.Hour)) {
		t.Fatal("refused submissions changed the account lock", failed, until)
	}
	now = lockedAt.Add(time.Hour - 31*time.Second) // nextCode advances 30s: one second before expiry
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); !errors.Is(err, ErrAccountAuth) {
		t.Fatal("account lock ended early", err)
	}
	// After expiry the count starts over instead of continuing from the limit.
	now = lockedAt.Add(time.Hour)
	fail(9, freshKey)
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); err != nil {
		t.Fatal("account lock did not expire or the count continued", err)
	}

	// A recovery code still completes login during the lock, and clears it.
	fail(10, freshKey)
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), codes[0]); err != nil {
		t.Fatal("recovery code refused during account lock", err)
	}
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); err != nil {
		t.Fatal("recovery code did not clear the account lock", err)
	}

	// Submissions refused by a per-key lock do not count toward the account.
	same := freshKey()
	fail(25, func() string { return same })
	if failed, _, _ := accountRow(); failed != 5 {
		t.Fatal("per-key refusals counted toward the account", failed)
	}
	fail(4, freshKey)
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); err != nil {
		t.Fatal("per-key refusals locked the account", err)
	}

	// Failures older than a day no longer count.
	fail(9, freshKey)
	now = now.Add(24*time.Hour + time.Second)
	fail(1, freshKey)
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); err != nil {
		t.Fatal("day-old failures still counted", err)
	}

	// Password reset and MFA reset both clear the account lock.
	fail(10, freshKey)
	if err = s.ChangePassword(a.AccountID, testAdminPassword+" changed", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := accountRow(); ok {
		t.Fatal("password reset kept the account lock")
	}
	if err = s.VerifySecondFactor(a.AccountID, freshKey(), nextCode()); err != nil {
		t.Fatal("password reset did not clear the account lock", err)
	}
	fail(10, freshKey)
	if err = s.DisableMFA(a.AccountID); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := accountRow(); ok {
		t.Fatal("MFA reset kept the account lock")
	}
	if got := lockouts(); len(got) != 4 {
		t.Fatalf("account lockout audits: %q", got)
	}
}
