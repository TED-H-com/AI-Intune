package operator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

type supervisionTestClock struct {
	mu sync.Mutex
	at time.Time
}

func (c *supervisionTestClock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.at }
func (c *supervisionTestClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.at = c.at.Add(d)
}

type supervisionTestBackend struct {
	mu                  sync.Mutex
	calls, active, peak int
	started             chan string
	release             <-chan struct{}
	err                 error
}

func (b *supervisionTestBackend) compute(ctx context.Context, kind string) error {
	b.mu.Lock()
	b.calls++
	b.active++
	b.peak = max(b.peak, b.active)
	err := b.err
	b.mu.Unlock()
	defer func() { b.mu.Lock(); b.active--; b.mu.Unlock() }()
	if b.started != nil {
		b.started <- kind
	}
	if b.release != nil {
		select {
		case <-b.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return err
}
func (b *supervisionTestBackend) count() (int, int) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.calls, b.peak
}
func (b *supervisionTestBackend) JobsSummary(ctx context.Context, f SupervisionFilter, at time.Time) (JobsSummary, error) {
	err := b.compute(ctx, "jobs")
	return JobsSummary{SchemaVersion: 1, EvaluatedAt: at, Filters: f, Items: []store.JobSummary{}}, err
}
func (b *supervisionTestBackend) ApprovalsSummary(ctx context.Context, window string, at time.Time) (ApprovalsSummary, error) {
	err := b.compute(ctx, "approvals")
	return ApprovalsSummary{SchemaVersion: 1, EvaluatedAt: at, Windows: []store.ApprovalSummaryWindow{}}, err
}
func (b *supervisionTestBackend) HubStatus(ctx context.Context, version string, started, at time.Time) (HubStatus, error) {
	err := b.compute(ctx, "status")
	return HubStatus{SchemaVersion: 1, EvaluatedAt: at, Version: version}, err
}
func newSupervisionTestService(b *supervisionTestBackend) (*SupervisionService, *supervisionTestClock) {
	s := NewSupervisionService(nil, "dev", time.Time{})
	s.backend = b
	clock := &supervisionTestClock{at: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	s.now = clock.now
	return s, clock
}

func TestSupervisionCacheHitExpiryAndNormalizedFilters(t *testing.T) {
	b := &supervisionTestBackend{}
	s, clock := newSupervisionTestService(b)
	f := SupervisionFilter{MachineID: "machine-a", Window: "24h"}
	first, err := s.JobsSummary(t.Context(), "local-user:operator-a", f)
	if err != nil {
		t.Fatal(err)
	}
	var dto JobsSummary
	if err := json.Unmarshal(first, &dto); err != nil || dto.CachedAt == nil || !dto.CachedAt.Equal(clock.now()) || dto.Items == nil {
		t.Fatalf("cache stamp %+v %v", dto, err)
	}
	clock.advance(29 * time.Second)
	f.PerMachine = true
	second, err := s.JobsSummary(t.Context(), "tailscale-user:operator-b", f)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("equivalent normalized filters missed cache")
	}
	if calls, _ := b.count(); calls != 1 {
		t.Fatalf("cache recomputed %d times", calls)
	}
	// The returned bytes cannot mutate the retained response.
	first[0] = '!'
	third, err := s.JobsSummary(t.Context(), "local-user:operator-a", f)
	if err != nil || third[0] != '{' {
		t.Fatal("caller mutated cached response")
	}
	clock.advance(time.Second)
	refreshed, err := s.JobsSummary(t.Context(), "local-user:operator-a", f)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(refreshed, &dto); err != nil || !dto.CachedAt.Equal(clock.now()) {
		t.Fatalf("stale cached_at %+v %v", dto, err)
	}
	if calls, _ := b.count(); calls != 2 {
		t.Fatalf("expired cache calls=%d", calls)
	}
	f.Window = "7d"
	if _, err := s.JobsSummary(t.Context(), "local-user:operator-a", f); err != nil {
		t.Fatal(err)
	}
	f.Window = ""
	if _, err := s.JobsSummary(t.Context(), "local-user:operator-a", f); err != nil {
		t.Fatal(err)
	}
	if calls, _ := b.count(); calls != 4 {
		t.Fatalf("different windows shared a cache entry: %d", calls)
	}
}

func TestSupervisionConcurrencyLimitAcrossRoutes(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	b := &supervisionTestBackend{started: make(chan string, 4), release: release}
	s, _ := newSupervisionTestService(b)
	s.waitBudget = 20 * time.Millisecond
	finished := make(chan error, 2)
	go func() {
		_, err := s.JobsSummary(t.Context(), "operator-a", SupervisionFilter{Kind: "noop"})
		finished <- err
	}()
	go func() { _, err := s.HubStatus(t.Context(), "operator-b"); finished <- err }()
	for i := 0; i < 2; i++ {
		select {
		case <-b.started:
		case <-time.After(time.Second):
			t.Fatal("computation did not enter")
		}
	}
	if _, err := s.ApprovalsSummary(t.Context(), "operator-c", "24h"); !errors.Is(err, ErrSupervisionBusy) {
		t.Fatalf("third computation not rejected: %v", err)
	}
	if calls, peak := b.count(); calls != 2 || peak != 2 {
		t.Fatalf("guard calls=%d peak=%d", calls, peak)
	}
	// Canceled requests cannot enter a computation or consume another slot.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := s.ApprovalsSummary(ctx, "operator-d", "7d"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation %v", err)
	}
	releaseAll()
	for i := 0; i < 2; i++ {
		select {
		case err := <-finished:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("slot leak")
		}
	}
	if _, err := s.ApprovalsSummary(t.Context(), "operator-c", "24h"); err != nil {
		t.Fatalf("guard did not recover: %v", err)
	}
}

func TestSupervisionPrincipalRateLimitIncludesCacheHitsAndAllRoutes(t *testing.T) {
	b := &supervisionTestBackend{}
	s, clock := newSupervisionTestService(b)
	for i := 0; i < SupervisionRateBurst; i++ {
		if _, err := s.HubStatus(t.Context(), "local-user:operator-a"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.JobsSummary(t.Context(), "local-user:operator-a", SupervisionFilter{Kind: "different"}); !errors.Is(err, ErrSupervisionRateLimited) {
		t.Fatalf("route/filter bypass: %v", err)
	}
	if calls, _ := b.count(); calls != 1 {
		t.Fatalf("rate-limited request computed: %d", calls)
	}
	if _, err := s.HubStatus(t.Context(), "local-user:operator-b"); err != nil {
		t.Fatalf("different subject denied: %v", err)
	}
	clock.advance(2 * time.Second)
	if _, err := s.HubStatus(t.Context(), "local-user:operator-a"); err != nil {
		t.Fatalf("refill did not admit: %v", err)
	}
	if _, err := s.HubStatus(t.Context(), ""); !errors.Is(err, ErrSupervisionSubjectRequired) {
		t.Fatalf("missing principal: %v", err)
	}
}

func TestSupervisionCacheCoalescesConcurrentMisses(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	defer releaseAll()
	b := &supervisionTestBackend{started: make(chan string, 2), release: release}
	s, _ := newSupervisionTestService(b)
	s.waitBudget = time.Second
	done := make(chan error, 2)
	go func() { _, err := s.HubStatus(t.Context(), "operator-a"); done <- err }()
	select {
	case <-b.started:
	case <-time.After(time.Second):
		t.Fatal("first read did not enter")
	}
	go func() { _, err := s.HubStatus(t.Context(), "operator-b"); done <- err }()
	// Wait until the second caller has completed rate admission. It must
	// share the first in-flight key instead of starting another computation.
	deadline := time.After(time.Second)
	for {
		s.mu.Lock()
		_, admitted := s.principals["operator-b"]
		s.mu.Unlock()
		if admitted {
			break
		}
		select {
		case <-deadline:
			t.Fatal("second read did not enter")
		default:
			time.Sleep(time.Millisecond)
		}
	}
	releaseAll()
	for i := 0; i < 2; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("same-key waiter leaked")
		}
	}
	if calls, peak := b.count(); calls != 1 || peak != 1 {
		t.Fatalf("duplicate computations calls=%d peak=%d", calls, peak)
	}
}

func TestSupervisionErrorsAreNotCachedAndStateIsBounded(t *testing.T) {
	b := &supervisionTestBackend{err: errors.New("read failed")}
	s, clock := newSupervisionTestService(b)
	for i := 0; i < 2; i++ {
		if _, err := s.HubStatus(t.Context(), "operator-a"); err == nil {
			t.Fatal("lost read error")
		}
	}
	if calls, _ := b.count(); calls != 2 {
		t.Fatal("failed result was cached")
	}
	b.err = nil
	for i := 0; i < SupervisionCacheEntries+2; i++ {
		if _, err := s.JobsSummary(t.Context(), fmt.Sprintf("operator-%d", i), SupervisionFilter{Kind: fmt.Sprintf("kind-%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	s.mu.Lock()
	size := len(s.cache)
	s.mu.Unlock()
	if size != SupervisionCacheEntries {
		t.Fatalf("unbounded cache: %d", size)
	}
	for i := 0; i < SupervisionPrincipalEntries; i++ {
		if err := s.admit(fmt.Sprintf("subject-%d", i), clock.now()); err != nil && !errors.Is(err, ErrSupervisionRateLimited) {
			t.Fatal(err)
		}
	}
	if err := s.admit("new-subject", clock.now()); !errors.Is(err, ErrSupervisionRateLimited) {
		t.Fatalf("active budget evicted: %v", err)
	}
	if len(s.principals) != SupervisionPrincipalEntries {
		t.Fatal("unbounded principal state")
	}
	clock.advance(time.Minute)
	if err := s.admit("new-subject", clock.now()); err != nil {
		t.Fatalf("idle budgets were not reclaimed: %v", err)
	}
}
