package web

import (
	"sync"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

// One fleet entry per Server; the lock also coalesces concurrent refreshes.
// Failures are cached too, so a database outage cannot cause a request stampede.
type diskAlertBannerCache struct {
	mu      sync.Mutex
	expires time.Time
	counts  store.DiskAlertBannerCounts
	err     error
}

func (c *diskAlertBannerCache) get(now time.Time, load func() (store.DiskAlertBannerCounts, error)) (store.DiskAlertBannerCounts, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !now.Before(c.expires) {
		c.counts, c.err = load()
		c.expires = now.Add(30 * time.Second)
	}
	return c.counts, c.err
}
