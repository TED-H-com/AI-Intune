package main

import (
	"bytes"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/store"
	"testing"
)

func TestOfflineAlertsCLIUsesCanonicalHTTPPreviewAndApply(t *testing.T) {
	f, _ := reportFixture(t)
	base, deps := reportCLIServer(t, f)
	run := func(args ...string) (string, error) {
		var out, errOut bytes.Buffer
		err := runOfflineAlertsCommand(t.Context(), append([]string{"--hub-url", base}, args...), &out, &errOut, deps)
		return out.String(), err
	}
	text, err := run()
	var settings store.OfflineAlertSettings
	if err != nil || json.Unmarshal([]byte(text), &settings) != nil || settings.Minutes != 10 {
		t.Fatalf("read %s %v", text, err)
	}
	text, err = run("--set-minutes", "3", "--preview")
	var preview store.OfflineAlertSettingsPreview
	if err != nil || json.Unmarshal([]byte(text), &preview) != nil || preview.Minutes != 3 {
		t.Fatalf("preview %s %v", text, err)
	}
	settings, _ = f.store.OfflineAlertSettings()
	if settings.Minutes != 10 {
		t.Fatal("CLI preview mutated")
	}
	if _, err = run("--set-minutes", "3", "--reason", "notify sooner"); err == nil {
		t.Fatal("CLI omitted confirmation")
	}
	text, err = run("--set-minutes", "3", "--reason", "notify sooner", "--confirm", "OFFLINE ALERTS")
	var applied store.OfflineAlertSettingsResult
	if err != nil || json.Unmarshal([]byte(text), &applied) != nil || applied.Settings.Minutes != 3 || applied.Settings.Revision != 1 {
		t.Fatalf("apply %s %v", text, err)
	}
	for _, args := range [][]string{{"--set-minutes", "0"}, {"--set-minutes", "5", "--idempotency-key", "partial"}, {"--set-minutes", "5", "--preview", "--preview-digest", "wrong"}, {"--db", "forbidden"}} {
		if _, err = run(args...); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}
