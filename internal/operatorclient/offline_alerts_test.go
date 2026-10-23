package operatorclient

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestOfflineAlertClientRejectsInvalidOrUnboundServerEvidence(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, body := range []string{`{"minutes":0,"revision":0}`, `{"minutes":1441,"revision":0}`, `{"minutes":10,"revision":-1}`, `{"minutes":10,"revision":0,"secret":"hidden"}`} {
		t.Run(body, func(t *testing.T) {
			client := settingClientServer(t, func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Cache-Control", "no-store")
				fmt.Fprint(w, body)
			})
			if _, err := client.OfflineAlertSettings(t.Context()); err == nil {
				t.Fatal("accepted invalid settings")
			}
		})
	}
	for _, body := range []string{
		fmt.Sprintf(`{"current":{"minutes":10,"revision":0},"minutes":6,"preview_digest":%q}`, digest),
		`{"current":{"minutes":10,"revision":0},"minutes":5,"preview_digest":"unbound"}`,
	} {
		client := settingClientServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, body)
		})
		if _, err := client.PreviewOfflineAlertSettings(t.Context(), 5); err == nil {
			t.Fatal("accepted unbound preview")
		}
	}
	rev := int64(0)
	req := store.OfflineAlertSettingsRequest{Minutes: 5, ExpectedRevision: &rev, PreviewDigest: digest, Reason: "review", Confirm: "OFFLINE ALERTS"}
	for _, body := range []string{`{"settings":{"minutes":6,"revision":1},"replayed":false}`, `{"settings":{"minutes":5,"revision":2},"replayed":false}`, `{"settings":{"minutes":5,"revision":1},"replayed":true}`} {
		client := settingClientServer(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			fmt.Fprint(w, body)
		})
		if _, err := client.ApplyOfflineAlertSettings(t.Context(), "offline-test", req); err == nil {
			t.Fatal("accepted unbound receipt")
		}
	}
}
