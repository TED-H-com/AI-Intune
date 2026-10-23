package main

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeObservationSource struct {
	ch      chan time.Time
	stopped bool
	resets  chan time.Duration
}

func (s *fakeObservationSource) C() <-chan time.Time   { return s.ch }
func (s *fakeObservationSource) Stop()                 { s.stopped = true }
func (s *fakeObservationSource) Reset(d time.Duration) { s.stopped = false; s.resets <- d }
func newFakeObservationSource() *fakeObservationSource {
	return &fakeObservationSource{ch: make(chan time.Time, 4), resets: make(chan time.Duration, 4)}
}

type fakeObservationClock struct {
	mu            sync.Mutex
	now           time.Time
	timer, ticker *fakeObservationSource
	ready         chan struct{}
}

func newFakeObservationClock() *fakeObservationClock {
	return &fakeObservationClock{now: time.Unix(1000, 0), timer: newFakeObservationSource(), ticker: newFakeObservationSource(), ready: make(chan struct{})}
}
func (c *fakeObservationClock) Now() time.Time                                { c.mu.Lock(); defer c.mu.Unlock(); return c.now }
func (c *fakeObservationClock) NewTimer(time.Duration) observationTimerSource { return c.timer }
func (c *fakeObservationClock) NewTicker(time.Duration) observationTimerSource {
	close(c.ready)
	return c.ticker
}
func (c *fakeObservationClock) advance(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	now := c.now
	c.mu.Unlock()
	c.ticker.ch <- now
}
func awaitObservation(t *testing.T, result <-chan observationWakeReason, want observationWakeReason) {
	t.Helper()
	select {
	case got := <-result:
		if got != want {
			t.Fatalf("wake = %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("wait did not return")
	}
}
func TestObservationWallWatchdog(t *testing.T) {
	c := newFakeObservationClock()
	result := make(chan observationWakeReason, 1)
	go func() { result <- waitObservation(context.Background(), 10*time.Minute, 0, nil, c, 0, nil) }()
	<-c.ready
	c.advance(11 * time.Minute)
	awaitObservation(t, result, observationTimer)
	if !c.timer.stopped || !c.ticker.stopped {
		t.Fatal("sources not stopped")
	}
}
func TestObservationSettingsRearm(t *testing.T) {
	c := newFakeObservationClock()
	var interval atomic.Int64
	interval.Store(int64(10 * time.Minute))
	result := make(chan observationWakeReason, 1)
	go func() {
		result <- waitObservation(context.Background(), 10*time.Minute, 0, nil, c, 10*time.Minute, func() time.Duration { return time.Duration(interval.Load()) })
	}()
	<-c.ready
	interval.Store(int64(time.Minute))
	c.advance(30 * time.Second)
	select {
	case d := <-c.timer.resets:
		if d != 30*time.Second {
			t.Fatalf("remaining = %v", d)
		}
	case <-time.After(time.Second):
		t.Fatal("timer not rearmed")
	}
	c.advance(31 * time.Second)
	awaitObservation(t, result, observationTimer)
}
func TestObservationCancelAndNudge(t *testing.T) {
	for _, cancelWait := range []bool{false, true} {
		c := newFakeObservationClock()
		ctx, cancel := context.WithCancel(context.Background())
		nudge := make(chan struct{}, 1)
		result := make(chan observationWakeReason, 1)
		go func() { result <- waitObservation(ctx, time.Hour, 0, nudge, c, 0, nil) }()
		<-c.ready
		want := observationNudged
		if cancelWait {
			cancel()
			want = observationCanceled
		} else {
			nudge <- struct{}{}
		}
		awaitObservation(t, result, want)
		cancel()
		if !c.timer.stopped || !c.ticker.stopped {
			t.Fatal("sources not stopped")
		}
	}
}
func TestObservationStopDrainBeforeReuse(t *testing.T) {
	source := newFakeObservationSource()
	source.ch <- time.Now()
	stopObservationTimer(source)
	source.Reset(time.Hour)
	select {
	case <-source.C():
		t.Fatal("stale timer fire survived reset")
	default:
	}
	stopObservationTimer(source)
	if !source.stopped {
		t.Fatal("source still active")
	}
}
func TestObservationOverdueUsesWallTime(t *testing.T) {
	now := time.Now()
	if !observationOverdue(now.Add(2*time.Minute), now, time.Minute) {
		t.Fatal("missed overdue observation")
	}
	if observationOverdue(now, now, time.Minute) {
		t.Fatal("fresh observation overdue")
	}
}
func TestOrphanSweepSkippedOutsideLinux(t *testing.T) {
	old := orphanSweepGOOS
	orphanSweepGOOS = "darwin"
	defer func() { orphanSweepGOOS = old }()
	done := make(chan struct{})
	var swept atomic.Bool
	launchJobs(context.Background(), func(context.Context) []string { swept.Store(true); return nil }, jobsOptions{}, func(context.Context, jobsOptions) { close(done) })
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("jobs did not start")
	}
	if swept.Load() {
		t.Fatal("orphan sweep ran on darwin")
	}
}
