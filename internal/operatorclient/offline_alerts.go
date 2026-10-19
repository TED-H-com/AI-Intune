package operatorclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/teddashh/AI-Intune/internal/store"
)

const offlineAlertSettingsPath = "/v1/operator/offline-alert-settings"

func validateOfflineSettings(s store.OfflineAlertSettings) error {
	if !store.ValidOfflineAlertMinutes(s.Minutes) || s.Revision < 0 {
		return errors.New("operator client: invalid offline alert settings")
	}
	return nil
}
func (c *Client) OfflineAlertSettings(ctx context.Context) (store.OfflineAlertSettings, error) {
	var out store.OfflineAlertSettings
	req, err := c.newOperatorRequest(ctx, http.MethodGet, offlineAlertSettingsPath, nil)
	if err != nil {
		return out, err
	}
	r, err := c.doRaw(req)
	if err != nil {
		return out, err
	}
	if r.status != 200 {
		return out, errors.New("operator client: unexpected offline settings status")
	}
	if err = validateSettingReadHeaders(r.header); err != nil {
		return out, err
	}
	if err = decodeStrictJSONDocument(r.body, "offline alert settings", &out); err != nil {
		return out, err
	}
	return out, validateOfflineSettings(out)
}
func (c *Client) PreviewOfflineAlertSettings(ctx context.Context, minutes int) (store.OfflineAlertSettingsPreview, error) {
	var out store.OfflineAlertSettingsPreview
	if !store.ValidOfflineAlertMinutes(minutes) {
		return out, errors.New("minutes must be 1..1440")
	}
	r, err := c.postSettingJSON(ctx, offlineAlertSettingsPath+"/preview", "", struct {
		Minutes int `json:"minutes"`
	}{minutes})
	if err != nil {
		return out, err
	}
	if r.status != 200 {
		return out, errors.New("operator client: unexpected offline preview status")
	}
	if err = validateSettingReadHeaders(r.header); err != nil {
		return out, err
	}
	if err = decodeStrictJSONDocument(r.body, "offline alert preview", &out); err != nil {
		return out, err
	}
	if out.Minutes != minutes || !validSHA256Digest(out.PreviewDigest) {
		return out, errors.New("operator client: invalid offline preview binding")
	}
	return out, validateOfflineSettings(out.Current)
}
func (c *Client) ApplyOfflineAlertSettings(ctx context.Context, key string, body store.OfflineAlertSettingsRequest) (store.OfflineAlertSettingsResult, error) {
	var out store.OfflineAlertSettingsResult
	if !validSettingIdempotencyKey(key) || body.ExpectedRevision == nil || *body.ExpectedRevision < 0 || !validSHA256Digest(body.PreviewDigest) || !store.ValidOfflineAlertMinutes(body.Minutes) || body.Confirm != "OFFLINE ALERTS" {
		return out, errors.New("operator client: invalid offline settings apply coordinates")
	}
	r, err := c.postSettingJSON(ctx, offlineAlertSettingsPath, key, body)
	if err != nil {
		return out, err
	}
	replayed, err := validateSettingWriteHeaders(r)
	if err != nil {
		return out, err
	}
	if r.status != 200 {
		return out, errors.New("operator client: unexpected offline apply status")
	}
	if err = decodeStrictJSONDocument(r.body, "offline alert apply", &out); err != nil {
		return out, err
	}
	expected := *body.ExpectedRevision
	if out.Settings.Minutes != body.Minutes || out.Replayed != replayed || (out.Settings.Revision != expected && out.Settings.Revision != expected+1) {
		return out, errors.New("operator client: offline apply result mismatch")
	}
	return out, validateOfflineSettings(out.Settings)
}
