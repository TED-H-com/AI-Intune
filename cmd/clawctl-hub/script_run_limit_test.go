package main

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestScriptRunRateLimitSubjectAndRefill(t *testing.T) {
	var limiter scriptRunRateLimiter
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for i := 0; i < scriptRunSubjectBurst; i++ {
		if !limiter.allow("tailscale-user:subject-a", now) {
			t.Fatal("legitimate burst denied")
		}
	}
	for i := 0; i < 100; i++ {
		if limiter.allow("tailscale-user:subject-a", now) {
			t.Fatal("exhausted subject admitted")
		}
	}
	if !limiter.allow("tailscale-user:subject-b", now) {
		t.Fatal("one exhausted subject blocked another")
	}
	if !limiter.allow("tailscale-user:subject-a", now.Add(2*time.Second)) || limiter.allow("tailscale-user:subject-a", now.Add(2*time.Second)) {
		t.Fatal("subject must refill at 30/minute")
	}
	if limiter.allow("tailscale-user:subject-a", now.Add(-time.Minute)) {
		t.Fatal("clock rollback refilled exhausted subject")
	}
	for i := 0; i < scriptRunSubjectBurst; i++ {
		if !limiter.allow("tailscale-user:subject-a", now.Add(62*time.Second)) {
			t.Fatal("full refill denied")
		}
	}
	if limiter.allow("tailscale-user:subject-a", now.Add(62*time.Second)) || limiter.allow("", now) {
		t.Fatal("exceeded or missing subject admitted")
	}
}

func TestScriptRunRateLimitGlobalAndBoundedSubjects(t *testing.T) {
	var limiter scriptRunRateLimiter
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for i := 0; i < scriptRunGlobalBurst; i++ {
		if !limiter.allow(fmt.Sprintf("tailscale-user:subject-%d", i), now) {
			t.Fatal("legitimate global burst denied")
		}
	}
	for i := 0; i < 1000; i++ {
		if limiter.allow(fmt.Sprintf("local-user:new-%d", i), now) {
			t.Fatal("global ceiling bypassed")
		}
	}
	if len(limiter.subjects) != scriptRunGlobalBurst {
		t.Fatal("globally rejected subjects grew limiter memory")
	}
	if !limiter.allow("local-user:new", now.Add(200*time.Millisecond)) || limiter.allow("local-user:new", now.Add(200*time.Millisecond)) {
		t.Fatal("global must refill at 300/minute")
	}
	// Subject rejections must not burn the shared quota.
	var shared scriptRunRateLimiter
	for i := 0; i < scriptRunSubjectBurst; i++ {
		_ = shared.allow("tailscale-user:exhausted", now)
	}
	for i := 0; i < 1000; i++ {
		_ = shared.allow("tailscale-user:exhausted", now)
	}
	for i := scriptRunSubjectBurst; i < scriptRunGlobalBurst; i++ {
		if !shared.allow(fmt.Sprintf("local-user:remaining-%d", i), now) {
			t.Fatal("subject rejection burned global tokens")
		}
	}
}

func TestScriptRunRateLimitConcurrency(t *testing.T) {
	var limiter scriptRunRateLimiter
	now := time.Now()
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if limiter.allow("tailscale-user:shared", now) {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	if accepted.Load() != scriptRunSubjectBurst {
		t.Fatalf("concurrent admission count=%d", accepted.Load())
	}
}

func TestScriptRunRateLimitDoesNotEvictActiveSubjects(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	limiter := scriptRunRateLimiter{subjects: make(map[string]scriptRunBucket), global: scriptRunBucket{tokens: scriptRunGlobalBurst, at: now}}
	for i := 0; i < scriptRunMaxSubjects; i++ {
		limiter.subjects[fmt.Sprintf("local-user:%d", i)] = scriptRunBucket{at: now}
	}
	if limiter.allow("local-user:new", now) || limiter.allow("local-user:0", now) || len(limiter.subjects) != scriptRunMaxSubjects {
		t.Fatal("cache pressure reset an active quota")
	}
	if !limiter.allow("local-user:new", now.Add(time.Minute)) || len(limiter.subjects) != 1 {
		t.Fatal("fully refilled idle quotas did not release cache capacity")
	}
}
