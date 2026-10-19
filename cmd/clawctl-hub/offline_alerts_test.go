package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/state"
	"github.com/teddashh/AI-Intune/internal/store"
)

type offlineFakeClock struct{ now time.Time }

func (c *offlineFakeClock) advance(d time.Duration) { c.now = c.now.Add(d) }

type offlineFakeNotifier struct {
	kinds, bodies []string
	fail          bool
}

func (n *offlineFakeNotifier) Notify(ctx context.Context, kind, body string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		return "fake", errors.New("missing deadline")
	}
	n.kinds = append(n.kinds, kind)
	n.bodies = append(n.bodies, body)
	if n.fail {
		return "fake", errors.New("fake delivery failed")
	}
	return "fake", nil
}
func offlineMachine(t *testing.T, h *hub, c *offlineFakeClock) string {
	t.Helper()
	id, token, err := h.store.CreateEnrollTokenFor("monitor-only", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = h.store.RedeemEnrollToken(token, model.EnrollRequest{SchemaVersion: model.SchemaVersion, EnrollToken: token, Hostname: "monitor", OS: "linux", Arch: "amd64"}, c.now)
	if err != nil {
		t.Fatal(err)
	}
	offlineHeartbeat(t, h, c, id)
	return id
}
func offlineHeartbeat(t *testing.T, h *hub, c *offlineFakeClock, id string) {
	t.Helper()
	if err := h.store.RecordCheckin(id, model.Checkin{SchemaVersion: model.SchemaVersion, SentAt: c.now.Add(48 * time.Hour), JobsEnabled: new(bool)}, c.now); err != nil {
		t.Fatal(err)
	}
}
func newOfflineFixture(t *testing.T) (*hub, *offlineFakeClock, *offlineFakeNotifier, string) {
	t.Helper()
	h := newHub(t, "")
	c := &offlineFakeClock{now: time.Now().UTC().Add(time.Minute).Truncate(time.Second)}
	n := &offlineFakeNotifier{}
	h.notifierOverride = n
	return h, c, n, offlineMachine(t, h, c)
}
func TestOfflineAlertsThresholdDedupeRecoveryAndDailyIsolation(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	stamp := filepath.Join(t.TempDir(), "daily-stamp")
	h.reportStamp = stamp
	c.advance(state.CheckinInterval + state.UnreachableGrace + 10*time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 0 {
		t.Fatal("alert at inclusive threshold")
	}
	c.advance(time.Second)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 || !strings.HasPrefix(n.kinds[0], "machine-offline:") || !strings.Contains(n.bodies[0], id) {
		t.Fatalf("missing monitor-only alert: %+v", n)
	}
	c.advance(24 * time.Hour)
	h.sendOfflineAlerts(c.now)
	if _, err := h.store.DB().Exec(`DELETE FROM notifications`); err != nil {
		t.Fatal(err)
	}
	restarted := &hub{store: h.store, notifierOverride: n, reportStamp: stamp}
	restarted.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("restart/retention repeated delivered outage")
	}
	offlineHeartbeat(t, h, c, id)
	h.sendOfflineAlerts(c.now)
	c.advance(store.OfflineRecoveryHold - time.Second)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("recovery did not wait for stable reporting")
	}
	c.advance(time.Second)
	h.sendOfflineAlerts(c.now)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 2 || n.kinds[1] != n.kinds[0]+":recovery" {
		t.Fatalf("bad recovery: %v", n.kinds)
	}
	if _, err := os.Stat(stamp); !os.IsNotExist(err) {
		t.Fatal("offline alert touched daily delivery stamp")
	}
	if rows := notificationRows(t, h, "daily"); rows != 0 {
		t.Fatal("offline alert consumed daily report")
	}
	h.reportAt = "00:00"
	h.maybeSendReport(c.now)
	h.maybeSendReport(c.now)
	if len(n.kinds) != 3 || n.kinds[2] != "daily" {
		t.Fatalf("daily report changed: %v", n.kinds)
	}
}
func TestOfflineAlertsFlapsAndFreshOutage(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	c.advance(14 * time.Minute)
	h.sendOfflineAlerts(c.now)
	offlineHeartbeat(t, h, c, id)
	h.sendOfflineAlerts(c.now)
	c.advance(time.Minute)
	h.sendOfflineAlerts(c.now)
	c.advance(3 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("brief recovery generated a flap notification")
	}
	offlineHeartbeat(t, h, c, id)
	h.sendOfflineAlerts(c.now)
	c.advance(store.OfflineRecoveryHold)
	h.sendOfflineAlerts(c.now)
	c.advance(12 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 3 || n.kinds[0] == n.kinds[2] {
		t.Fatalf("new outage not independent: %v", n.kinds)
	}
}
func TestOfflineAlertsFailedDeliveryBackoffAndNoOrphanRecovery(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	n.fail = true
	c.advance(14 * time.Minute)
	h.sendOfflineAlerts(c.now)
	c.advance(59 * time.Second)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("failure retried too early")
	}
	c.advance(time.Second)
	h.sendOfflineAlerts(c.now)
	c.advance(time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 2 {
		t.Fatal("second exponential backoff ignored")
	}
	// A new process uses the same durable failure schedule.
	h = &hub{store: h.store, notifierOverride: n}
	c.advance(time.Minute)
	n.fail = false
	h.sendOfflineAlerts(c.now)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 3 {
		t.Fatalf("successful retry not latched: %v", n.kinds)
	}
	// Another machine recovers before an alert was accepted: no orphan recovery.
	other := offlineMachine(t, h, c)
	n.fail = true
	c.advance(14 * time.Minute)
	h.sendOfflineAlerts(c.now)
	count := len(n.kinds)
	offlineHeartbeat(t, h, c, other)
	h.sendOfflineAlerts(c.now)
	c.advance(2 * time.Minute)
	n.fail = false
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != count {
		t.Fatal("recovery sent for undelivered outage")
	}
	_ = id
}
func TestOfflineAlertsRetirementNeverReportedAndUnconfigured(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	if _, _, err := h.store.CreateEnrollTokenFor("never-reported", time.Hour); err != nil {
		t.Fatal(err)
	}
	c.advance(14 * time.Minute)
	h.notifierOverride = nil
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 0 {
		t.Fatal("unconfigured notifier sent")
	}
	h.notifierOverride = n
	sends, err := h.store.ClaimOfflineAlerts(c.now)
	if err != nil || len(sends) != 1 {
		t.Fatalf("claim: %v %v", sends, err)
	}
	if err := h.store.RetireMachine(id, c.now); err != nil {
		t.Fatal(err)
	}
	if eligible, err := h.store.OfflineAlertEligible(sends[0], c.now); err != nil || eligible {
		t.Fatal("retired reservation remained eligible")
	}
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 0 {
		t.Fatal("retired/never-reported alerted")
	}
}
func TestOfflineAlertsSuccessfulAlertThenRetirementHasNoRecovery(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	c.advance(14 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if err := h.store.RetireMachine(id, c.now); err != nil {
		t.Fatal(err)
	}
	c.advance(24 * time.Hour)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("retired machine received recovery")
	}
	var rows int
	if err := h.store.DB().QueryRow(`SELECT COUNT(*) FROM machine_offline_alerts WHERE machine_id=?`, id).Scan(&rows); err != nil || rows != 0 {
		t.Fatalf("retired episode retained: %d %v", rows, err)
	}
}
func TestOfflineAlertsShortOutageBetweenSweepsResetsThreshold(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	c.advance(9 * time.Minute)
	h.sendOfflineAlerts(c.now)
	c.advance(time.Minute)
	offlineHeartbeat(t, h, c, id)
	c.advance(8 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 0 {
		t.Fatal("outages combined across a Hub heartbeat")
	}
	c.advance(6 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("new continuous outage not alerted")
	}
}

func TestOfflineAlertsConfiguredThresholdAndDurableReservation(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	p, err := h.store.PreviewOfflineAlertSettings(1)
	if err != nil {
		t.Fatal(err)
	}
	rev := p.Current.Revision
	_, err = h.store.ApplyOfflineAlertSettings(store.OfflineAlertSettingsRequest{Minutes: 1, ExpectedRevision: &rev, PreviewDigest: p.PreviewDigest, Reason: "short test threshold", Confirm: "OFFLINE ALERTS"}, "threshold-setting", store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	c.advance(state.CheckinInterval + state.UnreachableGrace + time.Minute + time.Second)
	first, err := h.store.ClaimOfflineAlerts(c.now)
	if err != nil || len(first) != 1 {
		t.Fatalf("claim: %v %v", first, err)
	}
	second, err := h.store.ClaimOfflineAlerts(c.now)
	if err != nil || len(second) != 0 {
		t.Fatal("reservation double claimed")
	}
	c.advance(2 * time.Minute)
	renewed, err := h.store.ClaimOfflineAlerts(c.now)
	if err != nil || len(renewed) != 1 || renewed[0].Token == first[0].Token || renewed[0].EpisodeID != first[0].EpisodeID {
		t.Fatalf("reservation not recoverable: %v %v", renewed, err)
	}
	if err := h.store.FinishOfflineAlert(first[0], true); err != nil {
		t.Fatal(err)
	}
	if valid, err := h.store.OfflineAlertEligible(renewed[0], c.now); err != nil || !valid {
		t.Fatal("stale completion changed reservation")
	}
	offlineHeartbeat(t, h, c, id)
	if valid, err := h.store.OfflineAlertEligible(renewed[0], c.now); err != nil || valid {
		t.Fatal("new heartbeat did not invalidate stale offline send")
	}
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 0 {
		t.Fatal("stale alert sent")
	}
}

func TestOfflineAlertStateSurvivesSQLiteReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "restart.sqlite")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	c := &offlineFakeClock{now: time.Now().UTC().Add(time.Minute).Truncate(time.Second)}
	n := &offlineFakeNotifier{}
	h := &hub{store: st, notifierOverride: n}
	id := offlineMachine(t, h, c)
	c.advance(14 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if err = st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h = &hub{store: st, notifierOverride: n}
	c.advance(time.Hour)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("SQLite reopen lost outage latch")
	}
	offlineHeartbeat(t, h, c, id)
	h.sendOfflineAlerts(c.now)
	c.advance(2 * time.Minute)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 2 || !strings.HasSuffix(n.kinds[1], ":recovery") {
		t.Fatal("SQLite reopen lost recovery")
	}
}

func TestOfflineAlertsRecheckClockAndChangedThresholdBeforeDelivery(t *testing.T) {
	h, c, n, _ := newOfflineFixture(t)
	c.advance(14 * time.Minute)
	started := c.now
	h.sendOfflineAlertsWithClock(started, func() time.Time {
		c.advance(2 * time.Minute)
		return c.now
	})
	if len(n.kinds) != 0 {
		t.Fatal("expired reservation sent after a delayed sweep")
	}
	c.advance(time.Minute)
	claims, err := h.store.ClaimOfflineAlerts(c.now)
	if err != nil || len(claims) != 1 {
		t.Fatalf("reclaim: %v %v", claims, err)
	}
	p, err := h.store.PreviewOfflineAlertSettings(60)
	if err != nil {
		t.Fatal(err)
	}
	rev := p.Current.Revision
	_, err = h.store.ApplyOfflineAlertSettings(store.OfflineAlertSettingsRequest{Minutes: 60, ExpectedRevision: &rev, PreviewDigest: p.PreviewDigest, Reason: "raise threshold", Confirm: "OFFLINE ALERTS"}, "raise-threshold", store.AuditEntry{})
	if err != nil {
		t.Fatal(err)
	}
	if valid, err := h.store.OfflineAlertEligible(claims[0], c.now); err != nil || valid {
		t.Fatal("old reservation ignored the increased threshold")
	}
}

func TestOfflineAlertsHeartbeatGapDuringSweepPauseResetsRecoveryHold(t *testing.T) {
	h, c, n, id := newOfflineFixture(t)
	c.advance(14 * time.Minute)
	h.sendOfflineAlerts(c.now)
	offlineHeartbeat(t, h, c, id)
	h.sendOfflineAlerts(c.now)
	// No sweeps during this lapse; the next heartbeat must restart the hold.
	c.advance(10 * time.Minute)
	offlineHeartbeat(t, h, c, id)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 1 {
		t.Fatal("an unobserved liveness gap completed recovery")
	}
	c.advance(store.OfflineRecoveryHold)
	h.sendOfflineAlerts(c.now)
	if len(n.kinds) != 2 {
		t.Fatal("fresh stable recovery did not send")
	}
}
