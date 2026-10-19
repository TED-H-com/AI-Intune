package operator

import "github.com/teddashh/AI-Intune/internal/store"

func (s *Service) OfflineAlertSettings() (store.OfflineAlertSettings, error) {
	return s.store.OfflineAlertSettings()
}
func (s *Service) PreviewOfflineAlertSettings(minutes int) (store.OfflineAlertSettingsPreview, error) {
	return s.store.PreviewOfflineAlertSettings(minutes)
}
func (s *Service) ApplyOfflineAlertSettings(req store.OfflineAlertSettingsRequest, key string, actor Actor) (store.OfflineAlertSettingsResult, error) {
	return s.store.ApplyOfflineAlertSettings(req, key, auditFromActor(actor))
}

// A malformed form has no canonical request and does not consume its key.
func (s *Service) RecordOfflineAlertTransportRejection(actor Actor) error {
	entry := auditFromActor(actor)
	entry.Action = store.AuditOfflineAlertSettings
	entry.Subject = "offline-alerts"
	entry.Detail = store.OperatorTransportRejectionPrefix + "invalid offline alert settings form"
	return s.store.RecordAudit(entry)
}
