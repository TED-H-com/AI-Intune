package web

import (
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineAlertSettingsWebReviewApplyAndReplay(t *testing.T) {
	s, st := newServer(t)
	body := get(t, s, offlineAlertsBack)
	for _, want := range []string{"離線通知", "10 分鐘", "僅監看", "已退役", "每日早報", `action="/tenant/offline-alerts/preview"`} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	preview := postForm(t, s, offlineAlertsBack+"/preview", url.Values{"minutes": {"8"}, "reason": {"notify sooner"}})
	if preview.Code != 200 || !strings.Contains(preview.Body.String(), "</html>") {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	form := url.Values{"minutes": {"8"}, "reason": {"notify sooner"}, "confirm": {"OFFLINE ALERTS"}}
	for _, key := range []string{"expected_revision", "preview_digest", "idempotency_key"} {
		form.Set(key, hiddenFormValue(t, preview.Body.String(), key))
	}
	for i := 0; i < 2; i++ {
		rec := postForm(t, s, offlineAlertsBack+"/apply", form)
		if rec.Code != 303 {
			t.Fatalf("apply: %d %s", rec.Code, rec.Body.String())
		}
	}
	settings, err := st.OfflineAlertSettings()
	if err != nil || settings.Minutes != 8 || settings.Revision != 1 {
		t.Fatalf("settings %+v %v", settings, err)
	}
	if dir := os.Getenv("CLAWCTL_OFFLINE_SCREENSHOT_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
		for name, html := range map[string]string{"settings": body, "review": preview.Body.String()} {
			if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(html), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestOfflineAlertSettingsMalformedFormsUseTheirOwnErrorAndAudit(t *testing.T) {
	s, st := newServer(t)
	for _, form := range []url.Values{
		{"minutes": {"5"}, "unknown": {"raw-sensitive-input"}},
		{"minutes": {"not-an-integer"}},
		{"minutes": {"5"}, "expected_revision": {"invalid"}},
	} {
		rec := postForm(t, s, offlineAlertsBack+"/apply", form)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "無法變更離線通知") || strings.Contains(rec.Body.String(), "Unable to complete disk operation") {
			t.Fatalf("wrong form error: %d %s", rec.Code, rec.Body.String())
		}
	}
	var count int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='offline-alert-settings' AND subject='offline-alerts' AND outcome='failed' AND detail NOT LIKE '%raw-sensitive-input%'`).Scan(&count); err != nil || count != 3 {
		t.Fatalf("wrong transport audit: %d %v", count, err)
	}
}
