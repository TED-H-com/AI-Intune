package web

import (
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/tailnet"
)

func TestMonitorOnlyProfileSSRPreviewConfirmAndHiddenActions(t *testing.T) {
	s, st := newServer(t)
	s.SetTailnetStatus(tailnet.Status{})
	id, ticket, err := st.CreateEnrollTokenFor("protected-appliance", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_ = ticket
	p := diskWebPrincipal(true, false, "")
	path := "/machines/" + id
	form := url.Values{"mode": {"monitor_only"}, "revision": {"1"}, "reason": {"protect appliance"}}
	preview := diskWebRequest(t, s, "POST", path+"/execution-policy/preview", form, p, false)
	if preview.Code != 200 {
		t.Fatalf("preview=%d %s", preview.Code, tail(preview.Body.String(), 1500))
	}
	saveProfileScreenshot(t, "profile-confirmation", preview.Body.String(), id)
	confirm := diskWebHidden(t, preview.Body.String(), "mode", "revision", "reason", "preview_digest", "idempotency_key")
	missing := diskWebRequest(t, s, "POST", path+"/execution-policy/apply", confirm, p, false)
	if missing.Code != 400 {
		t.Fatal("confirmation omitted", missing.Code)
	}
	confirm.Set("confirm", "yes")
	apply := diskWebRequest(t, s, "POST", path+"/execution-policy/apply", confirm, p, false)
	if apply.Code != 303 {
		t.Fatalf("apply=%d %s", apply.Code, apply.Body.String())
	}
	body := diskWebRequest(t, s, "GET", path, nil, p, false).Body.String()
	if !strings.Contains(body, "只監控 / Monitor only") || !strings.Contains(body, "</html>") {
		t.Fatal("missing profile badge or truncated page")
	}
	saveProfileScreenshot(t, "monitor-only-machine", body, id)
	for _, suffix := range []string{"/connect", "/terminals", "/diagnostic-noop-preview", "/channel", "/disks/approve"} {
		if strings.Contains(body, `action="`+path+suffix+`"`) {
			t.Fatal("monitor page contains action", suffix)
		}
	}
	if !strings.Contains(body, path+"/execution-policy/preview") {
		t.Fatal("no profile control")
	}
}

func saveProfileScreenshot(t *testing.T, name, body, id string) {
	t.Helper()
	dir := os.Getenv("CLAWCTL_PROFILE_SCREENSHOT_DIR")
	if dir == "" {
		return
	}
	body = strings.ReplaceAll(body, id, "fixture-protected-machine")
	body = regexp.MustCompile(`2026-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?`).ReplaceAllString(body, "2026-10-19 09:00")
	body = regexp.MustCompile(`name="idempotency_key" value="[^"]+"`).ReplaceAllString(body, `name="idempotency_key" value="fixture-profile-key"`)
	body = regexp.MustCompile(`name="preview_digest" value="[^"]+"`).ReplaceAllString(body, `name="preview_digest" value="fixture-preview"`)
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".html"), []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
}

func TestMonitorOnlySigninsHideIndividualAndBulkFlows(t *testing.T) {
	s, st := newServer(t)
	for _, id := range []string{"observed-monitor-one", "observed-monitor-two"} {
		if err := st.UpsertMachine(store.Machine{MachineID: id, DisplayName: id, OS: "linux", CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
		if err := st.RecordSigninHealth(id, []model.AuthHealth{{CLI: "agy", Slot: 1, Account: "fixture-account", Status: "logged_out"}}, time.Now().UTC()); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().Exec(`UPDATE machine_registry SET execution_policy='monitor_only' WHERE machine_id=?`, id); err != nil {
			t.Fatal(err)
		}
	}
	body := diskWebRequest(t, s, "GET", "/signins", nil, diskWebPrincipal(true, false, ""), false).Body.String()
	if strings.Contains(body, `action="/signins/start"`) || !strings.Contains(body, "只監控 / Monitor only") {
		t.Fatal("monitor sign-in controls exposed")
	}
}
