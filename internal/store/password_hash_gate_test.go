package store

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPasswordHashConcurrency(t *testing.T) {
	SetMaxConcurrentPasswordHashes(2)
	defer SetMaxConcurrentPasswordHashes(0)
	var active, peak atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			release, err := acquirePasswordHash(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			defer release()
			n := active.Add(1)
			for old := peak.Load(); n > old; old = peak.Load() {
				if peak.CompareAndSwap(old, n) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			active.Add(-1)
		}()
	}
	wg.Wait()
	if peak.Load() != 2 {
		t.Fatalf("peak=%d, want 2", peak.Load())
	}
}

func TestPasswordHashAcquisitionTimeout(t *testing.T) {
	SetMaxConcurrentPasswordHashes(1)
	defer SetMaxConcurrentPasswordHashes(0)
	release, err := acquirePasswordHash(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := acquirePasswordHash(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("got %v", err)
	}
}
