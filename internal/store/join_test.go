package store

import (
	"crypto/sha256"
	"path/filepath"
	"testing"
	"time"
)

func TestJoinExpiryPruningAndAtomicAudit(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC().Truncate(time.Second)
	expired := JoinRequest{Code: "ABCD-2345", Hostname: "host-b", OS: "linux", Arch: "amd64", User: "operator", CreatedAt: now.Add(-16 * time.Minute), ExpiresAt: now.Add(-time.Minute)}
	hash := sha256.Sum256([]byte("fixture-secret"))
	if err := st.StartJoin(expired, hash[:]); err != nil {
		t.Fatal(err)
	}
	if rows, err := st.ListJoins(now); err != nil || len(rows) != 0 {
		t.Fatal("expired listed", err)
	}
	j, err := st.LookupJoin(hash[:], now)
	if err != nil || !j.ExpiresAt.Before(now) {
		t.Fatal("expiry metadata lost", err)
	}
	if err := st.TransitionJoin(expired.Code, "pending", "approved", nil); err != ErrJoinState {
		t.Fatal("expired approved", err)
	}
	old := expired
	old.Code = "EFGH-2345"
	old.ExpiresAt = now.Add(-8 * 24 * time.Hour)
	oldHash := sha256.Sum256([]byte("old-secret"))
	if err := st.StartJoin(old, oldHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ListJoins(now); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.rdb.QueryRow(`SELECT count(*) FROM join_requests WHERE code=?`, old.Code).Scan(&n); err != nil || n != 0 {
		t.Fatal("old row not pruned", err)
	}
	active := expired
	active.Code = "JKLM-2345"
	active.ExpiresAt = now.Add(15 * time.Minute)
	activeHash := sha256.Sum256([]byte("active-secret"))
	if err := st.StartJoin(active, activeHash[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := st.db.Exec(`CREATE TRIGGER fail_join_audit BEFORE INSERT ON audit_log WHEN NEW.action='join_approve' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END`); err != nil {
		t.Fatal(err)
	}
	audit := AuditEntry{Action: AuditJoinApprove, Subject: active.Code, OK: true}
	if err := st.TransitionJoin(active.Code, "pending", "approved", &audit); err == nil {
		t.Fatal("missing audit accepted")
	}
	j, err = st.LookupJoin(activeHash[:], now)
	if err != nil || j.State != "pending" {
		t.Fatal("authority changed without audit", err)
	}
}
