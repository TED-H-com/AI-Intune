package main

import (
	"math"
	"sync"
	"time"
)

const (
	diskUploadPerMachineConcurrent = 2
	diskUploadGlobalConcurrent     = 16
	diskUploadMachineBurst         = 64 // one full 2 MiB report (32 chunks + completion), plus retries
	diskUploadMaxMachines          = 4096
)

type diskUploadMachine struct {
	bucket scriptRunBucket
	active int
}

// One Hub-owned admission gate covers chunk and completion requests. Only
// authenticated machine IDs are keys; changing job IDs or network origins
// cannot reset the per-machine allowance. Idle, fully refilled entries alone
// may be evicted, keeping both limiter memory and concurrency bounded.
type diskReportUploadLimiter struct {
	mu       sync.Mutex
	machines map[string]diskUploadMachine
	active   int
}

func (l *diskReportUploadLimiter) acquire(machine string, now time.Time) (func(), int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if machine == "" || l.active >= diskUploadGlobalConcurrent {
		return nil, 1
	}
	if l.machines == nil {
		l.machines = make(map[string]diskUploadMachine)
	}
	m, known := l.machines[machine]
	if !known {
		if len(l.machines) >= diskUploadMaxMachines {
			for key, old := range l.machines {
				if old.active == 0 && now.Sub(old.bucket.at) >= time.Minute {
					delete(l.machines, key)
				}
			}
			if len(l.machines) >= diskUploadMaxMachines {
				return nil, 1
			}
		}
		m.bucket = scriptRunBucket{tokens: diskUploadMachineBurst, at: now}
	}
	m.bucket = m.bucket.refill(now, diskUploadMachineBurst)
	if m.active >= diskUploadPerMachineConcurrent {
		return nil, 1
	}
	if m.bucket.tokens < 1 {
		l.machines[machine] = m
		return nil, max(1, int(math.Ceil((1-m.bucket.tokens)*60/diskUploadMachineBurst)))
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
