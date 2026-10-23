package store

import (
	"errors"
	"testing"
)

func TestOfflineAlertSettingsPreviewApplyReplayAndStale(t *testing.T) {
	s := newTestStore(t)
	before, err := s.OfflineAlertSettings()
	if err != nil || before.Minutes != 10 || before.Revision != 0 {
		t.Fatalf("defaults: %+v %v", before, err)
	}
	for _, n := range []int{-1, 0, 1441} {
		if _, err := s.PreviewOfflineAlertSettings(n); err == nil {
			t.Fatalf("accepted %d", n)
		}
	}
	p, err := s.PreviewOfflineAlertSettings(5)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := s.OfflineAlertSettings()
	if after != before {
		t.Fatal("preview mutated settings")
	}
	rev := p.Current.Revision
	req := OfflineAlertSettingsRequest{Minutes: 5, ExpectedRevision: &rev, PreviewDigest: p.PreviewDigest, Reason: "notify sooner", Confirm: "OFFLINE ALERTS"}
	out, err := s.ApplyOfflineAlertSettings(req, "offline-settings-test", AuditEntry{})
	if err != nil || out.Settings.Minutes != 5 || out.Settings.Revision != 1 || out.Replayed {
		t.Fatalf("apply: %+v %v", out, err)
	}
	replay, err := s.ApplyOfflineAlertSettings(req, "offline-settings-test", AuditEntry{})
	if err != nil || !replay.Replayed || replay.Settings != out.Settings {
		t.Fatalf("replay %+v %v", replay, err)
	}
	_, err = s.ApplyOfflineAlertSettings(req, "offline-stale", AuditEntry{})
	var rejection *OperatorRequestError
	if !errors.As(err, &rejection) || rejection.Code != OperatorCodeSettingPolicyConflict {
		t.Fatalf("stale result: %v", err)
	}
	req.Minutes = 6
	_, err = s.ApplyOfflineAlertSettings(req, "offline-settings-test", AuditEntry{})
	if !errors.As(err, &rejection) || rejection.Code != OperatorCodeIdempotencyConflict {
		t.Fatalf("key conflict: %v", err)
	}
}
