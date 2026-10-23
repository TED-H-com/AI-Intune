package main

import (
	"math"
	"sync"
	"time"
)

const (
	diskManifestPerMachineConcurrent = 2
	diskManifestGlobalConcurrent     = 16
	diskManifestMachineBurst         = 256 // up to 100 items with multiple grant renewals, plus retries
	diskManifestMaxMachines          = 4096
)

type diskManifestMachine struct {
	bucket scriptRunBucket
	active int
}

// One Hub-owned admission gate covers initial grants and renewals. Only
// authenticated machine IDs are keys; changing job IDs or network origins
// cannot reset the per-machine allowance. Idle, fully refilled entries alone
// may be evicted, keeping both limiter memory and concurrency bounded.
type diskManifestGrantLimiter struct {
	mu       sync.Mutex
	machines map[string]diskManifestMachine
	active   int
}

func (l *diskManifestGrantLimiter) acquire(machine string, now time.Time) (func(), int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if machine == "" || l.active >= diskManifestGlobalConcurrent {
		return nil, 1
	}
	if l.machines == nil {
		l.machines = make(map[string]diskManifestMachine)
	}
	m, known := l.machines[machine]
	if !known {
		if len(l.machines) >= diskManifestMaxMachines {
			for key, old := range l.machines {
				if old.active == 0 && now.Sub(old.bucket.at) >= time.Minute {
					delete(l.machines, key)
				}
			}
			if len(l.machines) >= diskManifestMaxMachines {
				return nil, 1
			}
		}
		m.bucket = scriptRunBucket{tokens: diskManifestMachineBurst, at: now}
	}
	m.bucket = m.bucket.refill(now, diskManifestMachineBurst)
	if m.active >= diskManifestPerMachineConcurrent {
		return nil, 1
	}
	if m.bucket.tokens < 1 {
		l.machines[machine] = m
		return nil, max(1, int(math.Ceil((1-m.bucket.tokens)*60/diskManifestMachineBurst)))
	}
	m.bucket.tokens--
	m.active++
	l.machines[machine] = m
	l.active++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			current := l.machines[machine]
			current.active--
			l.machines[machine] = current
			l.active--
		})
	}, 0
}
