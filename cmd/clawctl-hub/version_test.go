package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestVersionIsPublicBuildInformation(t *testing.T) {
	mux, _ := localAccountHandler(t)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "https://hub.example.com/version", nil))
	var got map[string]string
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil {
		t.Fatalf("response %d %s", w.Code, w.Body.String())
	}
	if len(got) != 3 || got["version"] != version || got["commit"] != commit || got["build_time"] != buildTime {
		t.Fatalf("unexpected build info: %v", got)
	}
}
