package main

import (
	"fmt"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDiskManifestConcurrentAndRateLimits(t *testing.T) {
	now := time.Now()
	var l diskManifestGrantLimiter
	a, _ := l.acquire("machine-a", now)
	b, _ := l.acquire("machine-a", now)
	if a == nil || b == nil {
		t.Fatal("legitimate concurrency rejected")
	}
	if r, retry := l.acquire("machine-a", now); r != nil || retry < 1 {
		t.Fatal("per-machine cap bypassed")
	}
	releases := []func(){a, b}
	for n := 2; n < diskManifestGlobalConcurrent; n++ {
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
	var rate diskManifestGrantLimiter
	for n := 0; n < diskManifestMachineBurst; n++ {
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

func TestDiskManifestLimiterConcurrentAdmission(t *testing.T) {
	var l diskManifestGrantLimiter
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
	if accepted.Load() != diskManifestPerMachineConcurrent {
		t.Errorf("concurrent admissions=%d", accepted.Load())
	}
	close(release)
	wg.Wait()
}

func TestDiskManifestLimiterMemoryBound(t *testing.T) {
	var l diskManifestGrantLimiter
	now := time.Now()
	for n := 0; n < diskManifestMaxMachines; n++ {
		r, _ := l.acquire(fmt.Sprint(n), now)
		if r == nil {
			t.Fatal("map rejected early")
		}
		r()
	}
	if r, _ := l.acquire("next", now); r != nil {
		t.Fatal("active rate bucket evicted")
	}
	if len(l.machines) != diskManifestMaxMachines {
		t.Fatal("limiter map unbounded")
	}
	if r, _ := l.acquire("next", now.Add(time.Minute)); r == nil {
		t.Fatal("idle map not pruned")
	} else {
		r()
	}
}

func TestDiskManifestHTTPAdmissionBeforeStore(t *testing.T) {
	for _, mode := range []string{"per-machine", "global", "rate"} {
		t.Run(mode, func(t *testing.T) {
			h := &hub{} // A nil store proves admission precedes writer and RSA signing.
			now := time.Now()
			count := diskManifestPerMachineConcurrent
			if mode == "global" {
				count = diskManifestGlobalConcurrent
			}
			if mode == "rate" {
				count = diskManifestMachineBurst
			}
			var releases []func()
			for n := 0; n < count; n++ {
				machine := "machine-a"
				if mode == "global" {
					machine = fmt.Sprint(n)
				}
				release, _ := h.diskManifestLimiter.acquire(machine, now)
				if release == nil {
					t.Fatal("fixture admission")
				}
				if mode == "rate" {
					release()
				} else {
					releases = append(releases, release)
				}
			}
			defer func() {
				for _, r := range releases {
					r()
				}
			}()
			if mode == "rate" {
				h.diskManifestLimiter.mu.Lock()
				m := h.diskManifestLimiter.machines["machine-a"]
				m.bucket.at = time.Now().Add(time.Hour)
				h.diskManifestLimiter.machines["machine-a"] = m
				h.diskManifestLimiter.mu.Unlock()
			}
			for _, id := range []string{"manifest-a", "expiry"} {
				r := httptest.NewRequest("GET", "/v1/ops-manifests/"+id+"?job_id=different-job&digest=changed", nil)
				r.SetPathValue("id", id)
				r.RemoteAddr = "192.0.2.99:9999"
				w := httptest.NewRecorder()
				h.handleDiskManifestFetch(w, r, "machine-a")
				retry, err := strconv.Atoi(w.Header().Get("Retry-After"))
				if w.Code != 429 || err != nil || retry < 1 || w.Header().Get("Cache-Control") != "no-store" {
					t.Fatal(w.Code, w.Header())
				}
			}
		})
	}
}

func TestDiskManifestHTTPPermitReleasedOnErrors(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	for _, path := range []string{"/v1/ops-manifests/missing", "/v1/ops-manifests/missing?job_id=missing&digest=sha256:" + strings.Repeat("a", 64)} {
		r := httptest.NewRequest("GET", path, nil)
		r.SetPathValue("id", "missing")
		w := httptest.NewRecorder()
		h.handleDiskManifestFetch(w, r, f.machine.id)
		if w.Code < 400 || w.Code == 429 {
			t.Fatal(w.Code, w.Body.String())
		}
		if h.diskManifestLimiter.active != 0 || h.diskManifestLimiter.machines[f.machine.id].active != 0 {
			t.Fatal("permit leaked on error")
		}
	}
}

func TestDiskManifestLimiterEvictionPreservesActiveEntries(t *testing.T) {
	var l diskManifestGrantLimiter
	now := time.Now()
	release, _ := l.acquire("active", now)
	for n := 1; n < diskManifestMaxMachines; n++ {
		r, _ := l.acquire(fmt.Sprint(n), now)
		if r == nil {
			t.Fatal("fixture admission")
		}
		r()
	}
	r, _ := l.acquire("new", now.Add(time.Minute))
	if r == nil {
		t.Fatal("expired idle entries not evicted")
	}
	r()
	if m, ok := l.machines["active"]; !ok || m.active != 1 {
		t.Fatal("active entry evicted")
	}
	release()
	release()
	if l.active != 0 || l.machines["active"].active != 0 {
		t.Fatal("permit ownership lost during eviction")
	}
}
