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
