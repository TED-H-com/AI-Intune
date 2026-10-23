package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestOfflineAlertSettingsAPIAndAuthorityParity(t *testing.T) {
	f, _ := reportFixture(t)
	read := reportGet(t, f, "/v1/operator/offline-alert-settings")
	if read.Code != 200 || read.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("read: %d %s", read.Code, read.Body.String())
	}
	var current store.OfflineAlertSettings
	if err := json.Unmarshal(read.Body.Bytes(), &current); err != nil || current.Minutes != 10 {
		t.Fatal("missing default settings")
	}
	preview := limitPost(t, f, "/v1/operator/offline-alert-settings/preview", `{"minutes":7}`, "")
	var p store.OfflineAlertSettingsPreview
	if preview.Code != 200 || json.Unmarshal(preview.Body.Bytes(), &p) != nil {
		t.Fatalf("preview: %d %s", preview.Code, preview.Body.String())
	}
	body := fmt.Sprintf(`{"minutes":7,"expected_revision":%d,"preview_digest":%q,"confirm":"OFFLINE ALERTS","reason":"reduce detection delay"}`, p.Current.Revision, p.PreviewDigest)
	for i := 0; i < 2; i++ {
		apply := limitPost(t, f, "/v1/operator/offline-alert-settings", body, "offline-api-test")
		if apply.Code != 200 {
			t.Fatalf("apply %d: %s", apply.Code, apply.Body.String())
		}
		if (apply.Header().Get("Idempotency-Replayed") == "true") != (i == 1) {
			t.Fatal("incorrect replay header")
		}
	}
	for _, body := range []string{`{"minutes":0}`, `{"minutes":1441}`, `{"minutes":5,"unknown":true}`, `{"minutes":5} {}`} {
		rec := limitPost(t, f, "/v1/operator/offline-alert-settings/preview", body, "")
		if rec.Code != 400 {
			t.Fatalf("bad preview %s: %d", body, rec.Code)
		}
	}
	// Every write adapter costs Admin; human-only eligibility is closed.
	for pattern, p := range operatorRoutePolicies {
		if pattern == "POST /v1/operator/offline-alert-settings" || pattern == "POST /v1/operator/offline-alert-settings/preview" || pattern == "POST /tenant/offline-alerts/preview" || pattern == "POST /tenant/offline-alerts/apply" {
			if p.Permission != operatorauth.Admin || p.ServiceTokenEligible != serviceIneligible {
				t.Fatalf("bad authority %s: %+v", pattern, p)
			}
		}
	}
	for _, path := range []string{"/v1/operator/offline-alert-settings?x=1", "/v1/operator/offline-alert-settings?"} {
		req := verifiedOperatorRequest(httptest.NewRequest(http.MethodGet, path, nil), operatorauth.View)
		rec := httptest.NewRecorder()
		f.mux.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("query accepted: %s", path)
		}
	}
}
