package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

func TestErrorAPI(t *testing.T) {
	t.Setenv("ERROR_INGEST_ENABLED", "true")
	file := filepath.Join(t.TempDir(), "read-token")
	if e := os.WriteFile(file, []byte("read-credential\n"), 0600); e != nil {
		t.Fatal(e)
	}
	t.Setenv("ERROR_READ_TOKEN_FILE", file)
	mux, st := emptyMetricsFixture(t)
	defer st.Close()
	m := enrollViaHTTP(t, mux, st, "error-machine")
	call := func(method, path, token string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, bytes.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	path := "/api/v1/machines/" + m.id + "/errors"
	record := errlog.Record{TS: time.Now().UTC(), MachineID: m.id, Component: "intune-agent", Code: "agent.failure", Level: "error", Msg: "failed ghp_testsecret", Fingerprint: "abc123", Count: 3, Context: map[string]any{"password": "hidden", "nested": []any{"Bearer secret-value"}}}
	raw, _ := json.Marshal([]errlog.Record{record})
	for _, tc := range []struct {
		path, token string
		want        int
	}{{path, "", 401}, {path, "read-credential", 401}, {"/api/v1/machines/other/errors", m.token, 403}} {
		if w := call("POST", tc.path, tc.token, raw); w.Code != tc.want {
			t.Fatalf("auth: %d %s", w.Code, w.Body)
		}
	}
	for i := 0; i < 2; i++ {
		w := call("POST", path, m.token, raw)
		if w.Code != 200 {
			t.Fatalf("ingest: %d %s", w.Code, w.Body)
		}
		want := `"inserted":1`
		if i == 1 {
			want = `"inserted":0`
		}
		if !strings.Contains(w.Body.String(), want) {
			t.Fatal(w.Body)
		}
	}
	// A body at the byte boundary is accepted, including JSON whitespace.
	padded := append(append([]byte{}, raw...), bytes.Repeat([]byte(" "), errorBatchBytes-len(raw))...)
	if w := call("POST", path, m.token, padded); w.Code != 200 {
		t.Fatalf("byte boundary: %d %s", w.Code, w.Body)
	}
	for _, token := range []string{"", m.token, "wrong"} {
		if w := call("GET", "/api/v1/errors", token, nil); w.Code != 401 {
			t.Fatalf("read auth: %d", w.Code)
		}
	}
	w := call("GET", "/api/v1/errors", "read-credential", nil)
	if w.Code != 200 || strings.Contains(w.Body.String(), "testsecret") || strings.Contains(w.Body.String(), "hidden") || !strings.Contains(w.Body.String(), "REDACTED") {
		t.Fatalf("read: %d %s", w.Code, w.Body)
	}
	w = call("GET", "/api/v1/errors/top", "read-credential", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"count":3`) {
		t.Fatalf("top: %d %s", w.Code, w.Body)
	}
	for _, body := range [][]byte{bytes.Repeat([]byte(" "), errorBatchBytes+1), []byte("[" + strings.Repeat(string(raw[1:len(raw)-1])+",", 200) + string(raw[1:len(raw)-1]) + "]")} {
		if w := call("POST", path, m.token, body); w.Code != 413 {
			t.Fatalf("limit: %d %s", w.Code, w.Body)
		}
	}
	record.MachineID = "other"
	raw, _ = json.Marshal([]errlog.Record{record})
	if w := call("POST", path, m.token, raw); w.Code != 403 {
		t.Fatalf("record auth: %d", w.Code)
	}
	for _, query := range []string{"?limit=0", "?limit=1001", "?since=bad"} {
		if w := call("GET", "/api/v1/errors"+query, "read-credential", nil); w.Code != 400 {
			t.Fatalf("query: %d", w.Code)
		}
	}
}

func TestErrorFlagOff(t *testing.T) {
	t.Setenv("ERROR_INGEST_ENABLED", "")
	mux, st := emptyMetricsFixture(t)
	defer st.Close()
	for _, route := range []struct{ method, path string }{{"POST", "/api/v1/machines/x/errors"}, {"GET", "/api/v1/errors"}, {"GET", "/api/v1/errors/top"}} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(route.method, route.path, nil))
		if w.Code != http.StatusNotFound {
			t.Fatalf("flag: %d", w.Code)
		}
	}
}

func TestErrorReadTokenMissing(t *testing.T) {
	t.Setenv("ERROR_INGEST_ENABLED", "true")
	t.Setenv("ERROR_READ_TOKEN_FILE", filepath.Join(t.TempDir(), "missing"))
	mux, st := emptyMetricsFixture(t)
	defer st.Close()
	for _, path := range []string{"/api/v1/errors", "/api/v1/errors/top"} {
		r := httptest.NewRequest("GET", path, nil)
		r.Header.Set("Authorization", "Bearer anything")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("missing token file: %d", w.Code)
		}
	}
}
