package operator

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func joinFixture(t *testing.T) (*Service, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st), st
}
func startFixture(t *testing.T, s *Service, ip string) JoinStarted {
	t.Helper()
	v, err := s.StartJoin(JoinStart{"host-b", "linux", "amd64", "operator"}, ip)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func approveFixture(t *testing.T, s *Service, code string) {
	t.Helper()
	if err := s.DecideJoin(context.Background(), code, "Host-B", true, "https://hub.example.com", JoinBundle{"https://hub.example.com/v1/join/bundle/amd64", strings.Repeat("a", 64)}, Actor{SourceKind: SourceKindWeb}); err != nil {
		t.Fatal(err)
	}
}
func TestJoinSingleUseConcurrentAndSecretFreeReads(t *testing.T) {
	s, st := joinFixture(t)
	v := startFixture(t, s, "192.0.2.1")
	if len(v.Secret) != 43 || len(v.Code) != 9 || v.PollSeconds != 5 || time.Until(v.ExpiresAt) > 15*time.Minute {
		t.Fatal("invalid join response")
	}
	if _, status, err := s.PollJoin(v.Secret); err != nil || status != 202 {
		t.Fatalf("pending: %d %v", status, err)
	}
	if !s.JoinBundleAuthorized(v.Secret, "amd64") || s.JoinBundleAuthorized(v.Secret, "arm64") {
		t.Fatal("bundle not bound to architecture")
	}
	approveFixture(t, s, v.Code)
	rows, err := s.ListJoins()
	if err != nil || len(rows) != 1 {
		t.Fatal("list", err)
	}
	encoded, _ := json.Marshal(rows)
	if strings.Contains(string(encoded), v.Secret) || strings.Contains(string(encoded), "enroll_token") {
		t.Fatal("read leaked secret")
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	var token string
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, status, err := s.PollJoin(v.Secret)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Error(err)
			}
			switch status {
			case 200:
				success++
				token = payload.EnrollToken
				if payload.Tailscale != nil || payload.DisplayName != "Host-B" || payload.HubURL != "https://hub.example.com" {
					t.Error("invalid approval")
				}
			case 410:
			default:
				t.Errorf("unexpected status %d", status)
			}
		}()
	}
	wg.Wait()
	if success != 1 || token == "" || s.JoinBundleAuthorized(v.Secret, "amd64") {
		t.Fatal("redemption was not single-use")
	}
	audit, err := st.Audit("", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range audit {
		if a.Action == store.AuditJoinApprove {
			found = true
		}
		b, _ := json.Marshal(a)
		if strings.Contains(string(b), token) || strings.Contains(string(b), v.Secret) {
			t.Fatal("audit leaked secret")
		}
	}
	if !found {
		t.Fatal("missing join decision audit")
	}
	hash := sha256.Sum256([]byte(v.Secret))
	j, err := st.LookupJoin(hash[:], time.Now())
	if err != nil || j.State != "redeemed" {
		t.Fatal("missing durable redemption", err)
	}
}
func TestJoinRestartRecoveryRejectionAndBounds(t *testing.T) {
	s, st := joinFixture(t)
	v := startFixture(t, s, "192.0.2.1")
	approveFixture(t, s, v.Code)
	restarted := New(st)
	if p, status, err := restarted.PollJoin(v.Secret); err != nil || status != 410 || p.State != "approval_expired" {
		t.Fatalf("restart: %d %s %v", status, p.State, err)
	}
	approveFixture(t, restarted, v.Code)
	if err := restarted.DecideJoin(context.Background(), v.Code, "", false, "", JoinBundle{}, Actor{}); err != nil {
		t.Fatal(err)
	}
	if p, status, err := restarted.PollJoin(v.Secret); err != nil || status != 410 || p.State != "rejected" {
		t.Fatal("rejection", status, err)
	}
	for i := 0; i < 5; i++ {
		startFixture(t, s, "192.0.2.2")
	}
	if _, err := s.StartJoin(JoinStart{"host-b", "linux", "amd64", "operator"}, "192.0.2.2"); !errors.Is(err, ErrJoinRate) {
		t.Fatal("missing IP limit", err)
	}
	for i := 5; i < 20; i++ {
		startFixture(t, s, fmt.Sprintf("192.0.2.%d", i+10))
	}
	if _, err := s.StartJoin(JoinStart{"host-b", "linux", "amd64", "operator"}, "192.0.2.99"); !errors.Is(err, store.ErrJoinFull) {
		t.Fatal("missing global limit", err)
	}
	if _, status, err := s.PollJoin(strings.Repeat("b", 43)); err != nil || status != 404 {
		t.Fatal("unknown secret", status, err)
	}
}
func TestJoinInputAndName(t *testing.T) {
	s, _ := joinFixture(t)
	for i, req := range []JoinStart{{"host", "linux", "amd64", "root"}, {"host", "windows", "amd64", "operator"}, {"host", "linux", "mips", "operator"}, {strings.Repeat("a", 254), "linux", "amd64", "operator"}, {"host\nname", "linux", "arm64", "operator"}} {
		if _, err := s.StartJoin(req, fmt.Sprint(i)); !errors.Is(err, ErrJoinInput) {
			t.Fatal("invalid input accepted", err)
		}
	}
	if JoinDisplayName("host-b") != "Host-B" || JoinDisplayName("host-ABC") != "Host-ABC" {
		t.Fatal("name rule")
	}
}

func TestJoinExpiredPollAndNoPlaintextPersistence(t *testing.T) {
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	s := New(st)
	secret := strings.Repeat("a", 43)
	hash := sha256.Sum256([]byte(secret))
	now := time.Now().UTC()
	if err := st.StartJoin(store.JoinRequest{Code: "ABCD-2345", Hostname: "host-b", OS: "linux", Arch: "amd64", User: "operator", CreatedAt: now.Add(-16 * time.Minute), ExpiresAt: now.Add(-time.Minute)}, hash[:]); err != nil {
		t.Fatal(err)
	}
	if p, status, err := s.PollJoin(secret); err != nil || status != 410 || p.State != "expired" {
		t.Fatalf("expired poll: %d %s %v", status, p.State, err)
	}
	started := startFixture(t, s, "192.0.2.1")
	approveFixture(t, s, started.Code)
	payload, status, err := s.PollJoin(started.Secret)
	if err != nil || status != 200 {
		t.Fatalf("approved poll: %d %v", status, err)
	}
	files, err := filepath.Glob(filepath.Join(dir, "hub.db*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, value := range []string{secret, started.Secret, payload.EnrollToken} {
			if strings.Contains(string(data), value) {
				t.Fatalf("plaintext credential persisted in %s", filepath.Base(file))
			}
		}
	}
}
