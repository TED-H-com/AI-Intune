package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiskUploadConcurrentAndRateLimits(t *testing.T) {
	now := time.Now()
	var l diskReportUploadLimiter
	a, _ := l.acquire("machine-a", now)
	b, _ := l.acquire("machine-a", now)
	if a == nil || b == nil {
		t.Fatal("legitimate concurrency rejected")
	}
	if r, retry := l.acquire("machine-a", now); r != nil || retry < 1 {
		t.Fatal("per-machine cap bypassed")
	}
	releases := []func(){a, b}
	for n := 2; n < diskUploadGlobalConcurrent; n++ {
		r, _ := l.acquire(fmt.Sprintf("machine-%d", n), now)
		if r == nil {
			t.Fatal("global admission rejected early")
		}
		releases = append(releases, r)
	}
	if r, retry := l.acquire("extra-machine", now); r != nil || retry < 1 {
		t.Fatal("global cap bypassed")
	}
	for _, r := range releases {
		r()
		r()
	}
	if l.active != 0 {
		t.Fatal("slots leaked or double-released")
	}
	var rate diskReportUploadLimiter
	for n := 0; n < diskUploadMachineBurst; n++ {
		r, _ := rate.acquire("machine-a", now)
		if r == nil {
			t.Fatal("burst rejected early")
		}
		r()
	}
	if r, retry := rate.acquire("machine-a", now); r != nil || retry < 1 {
		t.Fatal("rate cap bypassed")
	}
	if r, _ := rate.acquire("machine-b", now); r == nil {
		t.Fatal("machines share rate allowance")
	} else {
		r()
	}
	if r, _ := rate.acquire("machine-a", now.Add(time.Second)); r == nil {
		t.Fatal("refill unavailable")
	} else {
		r()
	}
}

func TestDiskUploadLimiterConcurrentAdmission(t *testing.T) {
	var l diskReportUploadLimiter
	var accepted atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	release := make(chan struct{})
	ready := make(chan struct{}, 32)
	for n := 0; n < 32; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			r, _ := l.acquire("machine-a", time.Now())
			if r != nil {
				accepted.Add(1)
			}
			ready <- struct{}{}
			<-release
			if r != nil {
				r()
			}
		}()
	}
	close(start)
	for n := 0; n < 32; n++ {
		<-ready
	}
	if accepted.Load() != diskUploadPerMachineConcurrent {
		t.Errorf("concurrent admissions=%d", accepted.Load())
	}
	close(release)
	wg.Wait()
}

func TestDiskUploadLimiterMemoryBound(t *testing.T) {
	var l diskReportUploadLimiter
	now := time.Now()
	for n := 0; n < diskUploadMaxMachines; n++ {
		r, _ := l.acquire(fmt.Sprint(n), now)
		if r == nil {
			t.Fatal("map rejected early")
		}
		r()
	}
	if r, _ := l.acquire("next", now); r != nil {
		t.Fatal("active rate bucket evicted")
	}
	if len(l.machines) != diskUploadMaxMachines {
		t.Fatal("limiter map unbounded")
	}
	if r, _ := l.acquire("next", now.Add(time.Minute)); r == nil {
		t.Fatal("idle map not pruned")
	} else {
		r()
	}
}

func TestDiskUploadHTTP429BeforeBodyOrStore(t *testing.T) {
	// Nil store proves rejected uploads never reach database operations.
	for _, mode := range []string{"per-machine", "global", "rate"} {
		t.Run(mode, func(t *testing.T) {
			h := &hub{}
			now := time.Now()
			var releases []func()
			count := diskUploadPerMachineConcurrent
			if mode == "global" {
				count = diskUploadGlobalConcurrent
			}
			if mode == "rate" {
				count = diskUploadMachineBurst
			}
			for n := 0; n < count; n++ {
				machine := "machine-a"
				if mode == "global" {
					machine = fmt.Sprint(n)
				}
				r, _ := h.diskUploadLimiter.acquire(machine, now)
				if r == nil {
					t.Fatal("fixture admission")
				}
				if mode == "rate" {
					r()
				} else {
					releases = append(releases, r)
				}
			}
			defer func() {
				for _, r := range releases {
					r()
				}
			}()
			for _, suffix := range []string{"chunks", "complete"} {
				req := httptest.NewRequest(http.MethodPost, "/v1/disk-reports/anything/"+suffix, bytes.NewBufferString("not JSON"))
				w := httptest.NewRecorder()
				h.handleDiskReportUpload(w, req, "machine-a")
				retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
				if w.Code != 429 || err != nil || retry < 1 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatalf("throttle response %d %v", w.Code, w.Header())
				}
			}
		})
	}
}
