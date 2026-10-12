package web

import (
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestDiskAlertBannerCacheConcurrencyExpiryAndErrors(t *testing.T) {
	var cache diskAlertBannerCache
	now := time.Now()
	calls := 0
	load := func() (store.DiskAlertBannerCounts, error) {
		calls++
		return store.DiskAlertBannerCounts{OpenCritical: 2}, nil
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			counts, err := cache.get(now, load)
			if err != nil || counts.OpenCritical != 2 {
				t.Error(counts, err)
			}
		}()
	}
	wg.Wait()
	if calls != 1 {
		t.Fatalf("concurrent refresh calls=%d", calls)
	}
	cache.get(now.Add(29*time.Second), load)
	if calls != 1 {
		t.Fatal("refreshed before TTL")
	}
	cache.get(now.Add(30*time.Second), load)
	if calls != 2 {
		t.Fatal("failed to refresh at TTL")
	}
	failed := func() (store.DiskAlertBannerCounts, error) {
		calls++
		return store.DiskAlertBannerCounts{}, errors.New("unavailable")
	}
	for i := 0; i < 10; i++ {
		if _, err := cache.get(now.Add(time.Minute), failed); err == nil {
			t.Fatal("failure lost")
		}
	}
	if calls != 3 {
		t.Fatalf("failure stampede calls=%d", calls)
	}
}

func TestDiskAlertBannerRenderUsesOnlyOpenCounts(t *testing.T) {
	s, st := newServer(t)
	machine := onlineMachine(t, st, "example-device")
	if _, err := st.DB().Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,last_reading) VALUES('banner',?,'banner','critical',?,?)`, machine, time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	// Full supervision would query both of these tables and suppress the banner.
	for _, table := range []string{"disk_canary_days", "disk_ownership"} {
		if _, err := st.DB().Exec(`DROP TABLE ` + table); err != nil {
			t.Fatal(err)
		}
	}
	render := func() string {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/tenant/disk-alerts", nil)
		s.render(w, r, "disk_alerts.html", page{Title: "Disk alerts", DiskAlerts: &diskAlertsPage{}})
		return w.Body.String()
	}
	if !strings.Contains(render(), "Disk alerts: 1 critical") {
		t.Fatal("banner did not use narrow query")
	}
	if _, err := st.DB().Exec(`DELETE FROM disk_alerts`); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(render(), "Disk alerts: 1 critical") {
		t.Fatal("banner bypassed cache")
	}
	s.diskAlertBanner.mu.Lock()
	s.diskAlertBanner.expires = time.Time{}
	s.diskAlertBanner.mu.Unlock()
	if strings.Contains(render(), "Disk alerts: 1 critical") {
		t.Fatal("banner did not refresh")
	}
}
