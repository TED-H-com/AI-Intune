package main

import (
	"context"
	"time"
)

const observationGrace = time.Second

type observationTimerClock interface {
	Now() time.Time
	NewTimer(time.Duration) observationTimerSource
	NewTicker(time.Duration) observationTimerSource
}

type observationTimerSource interface {
	C() <-chan time.Time
	Stop()
	Reset(time.Duration)
}

type realObservationClock struct{}

func (realObservationClock) Now() time.Time { return time.Now() }
func (realObservationClock) NewTimer(d time.Duration) observationTimerSource {
	return realObservationTimer{time.NewTimer(d)}
}
func (realObservationClock) NewTicker(d time.Duration) observationTimerSource {
	return realObservationTicker{time.NewTicker(d)}
}

type realObservationTimer struct{ timer *time.Timer }

func (t realObservationTimer) C() <-chan time.Time   { return t.timer.C }
func (t realObservationTimer) Stop()                 { t.timer.Stop() }
func (t realObservationTimer) Reset(d time.Duration) { t.timer.Reset(d) }

type realObservationTicker struct{ ticker *time.Ticker }

func (t realObservationTicker) C() <-chan time.Time   { return t.ticker.C }
func (t realObservationTicker) Stop()                 { t.ticker.Stop() }
func (t realObservationTicker) Reset(d time.Duration) { t.ticker.Reset(d) }

// Stop and drain before either resetting or abandoning a source. The wait loop
// is its only receiver, so a nonblocking drain also supports pre-Go 1.23 timers.
func stopObservationTimer(t observationTimerSource) {
	t.Stop()
	select {
	case <-t.C():
	default:
	}
}

func observationOverdue(now, last time.Time, interval time.Duration) bool {
	return now.Round(0).Sub(last.Round(0)) > interval+observationGrace
}

// currentInterval is optional; polling it avoids coupling settings adoption to
// the observation loop. Deadlines use wall time so host sleep counts as elapsed.
func waitObservation(ctx context.Context, wait, floor time.Duration, nudge <-chan struct{}, clock observationTimerClock, interval time.Duration, currentInterval func() time.Duration) observationWakeReason {
	wait = max(wait, 0)
	floor = min(max(floor, 0), wait)
	start := clock.Now().Round(0)
	deadline := start.Add(wait)
	floorDeadline := start.Add(floor)
	timer := clock.NewTimer(wait)
	defer stopObservationTimer(timer)
	watchdog := clock.NewTicker(max(time.Millisecond, min(wait, 30*time.Second)))
	defer stopObservationTimer(watchdog)
	var floorTimer observationTimerSource
	var floorC <-chan time.Time
	if floor > 0 && floor < wait {
		floorTimer = clock.NewTimer(floor)
		floorC = floorTimer.C()
		defer stopObservationTimer(floorTimer)
	}
	var nudgeC <-chan struct{}
	if floor == 0 {
		nudgeC = nudge
	}
	for {
		select {
		case <-ctx.Done():
			return observationCanceled
		case <-timer.C():
			return observationTimer
		case <-nudgeC:
			return observationNudged
		case <-floorC:
			nudgeC = nudge
			floorC = nil
		case <-watchdog.C():
			now := clock.Now().Round(0)
			if currentInterval != nil {
				if next := currentInterval(); next != interval {
					interval = next
					deadline = start.Add(max(next, floor))
					stopObservationTimer(timer)
					timer.Reset(max(deadline.Sub(now), 0))
				}
			}
			if !now.Before(deadline.Add(observationGrace)) {
				return observationTimer
			}
			if floor < wait && !now.Before(floorDeadline) {
				nudgeC = nudge
			}
		}
	}
}
