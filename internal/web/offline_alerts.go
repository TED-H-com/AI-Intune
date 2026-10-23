package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

const offlineAlertsBack = "/tenant/offline-alerts"

type offlineAlertsPage struct {
	Settings    store.OfflineAlertSettings
	Preview     *store.OfflineAlertSettingsPreview
	Reason, Key string
}

func (s *Server) offlineAlertsRoutes(mux *http.ServeMux) []string {
	patterns := []string{"GET /tenant/offline-alerts", "POST /tenant/offline-alerts/preview", "POST /tenant/offline-alerts/apply"}
	for _, p := range patterns {
		mux.HandleFunc(p, s.offlineAlerts)
	}
	return patterns
}
func (s *Server) offlineAlerts(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		http.Error(w, "query parameters not supported", 400)
		return
	}
	view := offlineAlertsPage{}
	if r.Method == http.MethodGet {
		settings, err := s.operator.OfflineAlertSettings()
		if err != nil {
			s.fail(w, "讀取離線通知設定失敗", err)
			return
		}
		view.Settings = settings
	} else {
		if !operatorWebForm(w, r, nil, "minutes", "reason", "expected_revision", "preview_digest", "idempotency_key", "confirm") {
			s.offlineAlertFormError(w, r)
			return
		}
		raw := r.PostForm.Get("minutes")
		minutes, err := strconv.Atoi(raw)
		if err != nil || strconv.Itoa(minutes) != raw {
			s.offlineAlertFormError(w, r)
			return
		}
		if r.URL.Path == offlineAlertsBack+"/preview" {
			preview, err := s.operator.PreviewOfflineAlertSettings(minutes)
			if err != nil {
				s.offlineAlertError(w, r, err)
				return
			}
			key, err := operator.NewIdempotencyKey("web-offline-alerts")
			if err != nil {
				s.fail(w, "Unable to create request key", err)
				return
			}
			view = offlineAlertsPage{Settings: preview.Current, Preview: &preview, Reason: r.PostForm.Get("reason"), Key: key}
		} else {
			rev, err := strconv.ParseInt(r.PostForm.Get("expected_revision"), 10, 64)
			if err != nil || rev < 0 {
				s.offlineAlertFormError(w, r)
				return
			}
			_, err = s.operator.ApplyOfflineAlertSettings(store.OfflineAlertSettingsRequest{Minutes: minutes, ExpectedRevision: &rev, PreviewDigest: r.PostForm.Get("preview_digest"), Reason: r.PostForm.Get("reason"), Confirm: r.PostForm.Get("confirm")}, r.PostForm.Get("idempotency_key"), operator.ActorFromRequest(r, operator.SourceKindWeb))
			if err != nil {
				s.offlineAlertError(w, r, err)
				return
			}
			http.Redirect(w, r, offlineAlertsBack, http.StatusSeeOther)
			return
		}
	}
	s.render(w, r, "offline_alerts.html", page{Title: "離線通知", Nav: "tenant-offline-alerts", Now: time.Now().Local().Format("2006-01-02 15:04"), OfflineAlerts: &view})
}

func (s *Server) offlineAlertFormError(w http.ResponseWriter, r *http.Request) {
	if err := s.operator.RecordOfflineAlertTransportRejection(operator.ActorFromRequest(r, operator.SourceKindWeb)); err != nil {
		s.fail(w, "Unable to record offline alert settings rejection", err)
		return
	}
	s.renderActionStatus(w, r, 400, "離線通知", "無法變更離線通知", "Invalid form. Return to the page and preview again.", offlineAlertsBack)
}

func (s *Server) offlineAlertError(w http.ResponseWriter, r *http.Request, err error) {
	status, _, detail := operator.HTTPError(err)
	s.renderActionStatus(w, r, status, "離線通知", "無法變更離線通知", detail, offlineAlertsBack)
}
