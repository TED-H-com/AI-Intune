package store

// Before/after harness: CLAWCTL_PERF=1 go test -run TestHubPerfCompare -v ./internal/store/
// Uses production argon2id parameters and only APIs present on main and on this branch.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func perfPct(d []time.Duration, p float64) time.Duration {
	if len(d) == 0 {
		return 0
	}
	sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
	return d[int(float64(len(d)-1)*p)]
}

func perfSize(path string) int64 {
	var n int64
	for _, suf := range []string{"", "-wal"} {
		if fi, err := os.Stat(path + suf); err == nil {
			n += fi.Size()
		}
	}
	return n
}

func TestHubPerfCompare(t *testing.T) {
	if os.Getenv("CLAWCTL_PERF") == "" {
		t.Skip("set CLAWCTL_PERF=1")
	}
	path := filepath.Join(t.TempDir(), "perf.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.CreateFirstAdmin("admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	base := time.Now().UTC()
	old := base.Add(-40 * 24 * time.Hour)
	var machines []string
	for i := 0; i < 8; i++ {
		tok, err := s.CreateEnrollToken(fmt.Sprintf("perf-%d", i), time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		m, _, err := s.RedeemEnrollToken(tok, model.EnrollRequest{SchemaVersion: model.SchemaVersion, EnrollToken: tok, Hostname: fmt.Sprintf("perf-%d", i), OS: "linux", Arch: "amd64", UnixUser: "example-user"}, old)
		if err != nil {
			t.Fatal(err)
		}
		machines = append(machines, m)
	}
	batch := func(at time.Time) model.ObservationBatch {
		b := healthyBatch(at)
		for i := 0; i < 250; i++ {
			b.Systemd = append(b.Systemd, model.Unit{Name: fmt.Sprintf("unit-%d.service", i)})
		}
		return b
	}
	// Seed expired history for the prune measurement.
	for i := 0; i < 40; i++ {
		at := old.Add(time.Duration(i) * time.Minute)
		if err := s.RecordObservation(machines[i%len(machines)], batch(at), at); err != nil {
			t.Fatal(err)
		}
	}
	// Load: 4 writers loop RecordObservation while logins run.
	stop := make(chan struct{})
	var obs atomic.Int64
	var wg sync.WaitGroup
	var obsMu sync.Mutex
	var obsDur []time.Duration
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; ; i++ {
				select {
				case <-stop:
					return
				default:
				}
				now := time.Now().UTC()
				st := time.Now()
				if err := s.RecordObservation(machines[(w*2+i)%len(machines)], batch(now), now); err != nil {
					t.Error(err)
					return
				}
				d := time.Since(st)
				obsMu.Lock()
				obsDur = append(obsDur, d)
				obsMu.Unlock()
				obs.Add(1)
			}
		}(w)
	}
	// Optional: emulate the live 1-2s record_observation holds seen on the
	// shared-cpu-2x Hub (CLAWCTL_PERF_HOLD=1500ms).
	if hold, _ := time.ParseDuration(os.Getenv("CLAWCTL_PERF_HOLD")); hold > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				tx, err := s.beginWrite(context.Background(), "record_observation_slow")
				if err != nil {
					continue
				}
				time.Sleep(hold)
				tx.Rollback()
			}
		}()
	}
	time.Sleep(500 * time.Millisecond)
	start := time.Now()
	var lmu sync.Mutex
	lat := map[string][]time.Duration{}
	var lw sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i := 0; i < 48; i++ {
		kind, pw := "ok", testAdminPassword
		if i%2 == 1 {
			kind, pw = "wrong", "wrong-password"
		}
		ip := fmt.Sprintf("198.51.100.%d", i) // distinct IPs: no lockout during measurement
		lw.Add(1)
		sem <- struct{}{}
		go func() {
			defer lw.Done()
			defer func() { <-sem }()
			st := time.Now()
			_, err := s.VerifyPassword("admin", pw, ip)
			d := time.Since(st)
			if kind == "ok" && err != nil {
				kind = "ok-error"
			}
			if kind == "wrong" && !errors.Is(err, ErrAccountAuth) {
				kind = "wrong-error"
			}
			lmu.Lock()
			lat[kind] = append(lat[kind], d)
			lmu.Unlock()
		}()
	}
	lw.Wait()
	window := time.Since(start)
	close(stop)
	wg.Wait()
	for k, d := range lat {
		t.Logf("PERF login %-11s n=%d p50=%v p95=%v max=%v", k, len(d), perfPct(d, .5).Round(time.Millisecond), perfPct(d, .95).Round(time.Millisecond), perfPct(d, 1).Round(time.Millisecond))
	}
	t.Logf("PERF observations %d in %v (load running) = %.1f/s; call p50=%v p95=%v", obs.Load(), window.Round(time.Millisecond), float64(obs.Load())/window.Seconds(), perfPct(obsDur, .5).Round(time.Millisecond), perfPct(obsDur, .95).Round(time.Millisecond))
	s.gate.stats.mu.Lock()
	for name, h := range s.gate.stats.hold {
		h.mu.Lock()
		if h.count > 0 {
			t.Logf("PERF writer hold %-22s n=%d mean=%.1fms", name, h.count, h.sum/float64(h.count)*1000)
		}
		h.mu.Unlock()
	}
	s.gate.stats.mu.Unlock()
	before := perfSize(path)
	st := time.Now()
	rep, err := s.Prune(time.Now().UTC(), DefaultRetention(), false)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("PERF prune deleted=%d in %v; db+wal before=%.1fMB after=%.1fMB (wal after=%.1fMB)", rep.Total(), time.Since(st).Round(time.Millisecond), float64(before)/1e6, float64(perfSize(path))/1e6, float64(perfSize(path)-perfSize(path+"x"))/1e6-float64(func() int64 {
		fi, _ := os.Stat(path)
		if fi == nil {
			return 0
		}
		return fi.Size()
	}())/1e6)
}
