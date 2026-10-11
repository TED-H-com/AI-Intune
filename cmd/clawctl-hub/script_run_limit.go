package main

import (
	"sync"
	"time"
)

const (
	scriptRunSubjectBurst = 30
	scriptRunGlobalBurst  = 300
	scriptRunMaxSubjects  = 4096
)

type scriptRunBucket struct {
	tokens float64
	at     time.Time
}

func (b scriptRunBucket) refill(now time.Time, burst int) scriptRunBucket {
	if now.After(b.at) {
		b.tokens = min(float64(burst), b.tokens+now.Sub(b.at).Seconds()*float64(burst)/60)
		b.at = now
	}
	return b
}

// One process-local limiter covers both preview and apply, including replays.
// Only authenticated StableSubject values enter this bounded map; neither IP
// addresses nor caller-supplied request coordinates create fresh allowances.
type scriptRunRateLimiter struct {
	mu       sync.Mutex
	subjects map[string]scriptRunBucket
	global   scriptRunBucket
}

func (l *scriptRunRateLimiter) allow(subject string, now time.Time) bool {
	if subject == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.subjects == nil {
		l.subjects = make(map[string]scriptRunBucket)
		l.global = scriptRunBucket{tokens: scriptRunGlobalBurst, at: now}
	}
	l.global = l.global.refill(now, scriptRunGlobalBurst)
	if l.global.tokens < 1 {
		return false
	}
	bucket, known := l.subjects[subject]
	if known {
		bucket = bucket.refill(now, scriptRunSubjectBurst)
		if bucket.tokens < 1 {
			return false
		}
	} else {
		if len(l.subjects) >= scriptRunMaxSubjects {
			// Idle for a full refill period means removal cannot grant extra tokens.
			// Never evict an exhausted active subject into a fresh burst.
			for key, b := range l.subjects {
				if now.Sub(b.at) >= time.Minute {
					delete(l.subjects, key)
				}
			}
			if len(l.subjects) >= scriptRunMaxSubjects {
				return false
			}
		}
		bucket = scriptRunBucket{tokens: scriptRunSubjectBurst, at: now}
	}
	bucket.tokens--
	l.subjects[subject] = bucket
	l.global.tokens--
	return true
}
