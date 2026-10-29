package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

func uploadRecord(i int, msg string) []byte {
	b, _ := json.Marshal(errlog.Record{TS: time.Unix(int64(i+1), 0).UTC(), Component: "bat-session", Code: "session.failed", Level: "error", Count: 1, Msg: msg, Context: map[string]any{"password": "opaque", "nested": []any{map[string]any{"msg": "Bearer hidden-value"}}}})
	return append(b, '\n')
}
func uploadFixture(t *testing.T, handler http.HandlerFunc) (*errorUploader, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "errors.jsonl")
	previous := httpClient
	httpClient = &http.Client{Transport: errorUploadTransport(func(r *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, r)
		return recorder.Result(), nil
	})}
	t.Cleanup(func() { httpClient = previous })
	t.Setenv("AI_INTUNE_ERROR_LOG", path)
	t.Setenv("AI_INTUNE_BAT_ERROR_LOGS", "")
	u, err := newErrorUploader(config{HubURL: "http://hub.test", MachineID: "machine", AgentToken: "credential"}, filepath.Join(dir, "cursor.json"))
	if err != nil {
		t.Fatal(err)
	}
	return u, path
}
func mustUpload(t *testing.T, u *errorUploader) {
	t.Helper()
	if err := u.upload(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func writeUpload(t *testing.T, path string, b []byte) {
	t.Helper()
	if err := os.WriteFile(path, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestErrorUploadBatchingAndRedaction(t *testing.T) {
	for _, length := range []int{10, 3000} {
		t.Run(strings.Repeat("x", min(length, 10)), func(t *testing.T) {
			total, calls := 0, 0
			u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/v1/machines/machine/errors" || r.Header.Get("Authorization") != "Bearer credential" {
					t.Error("incorrect request authentication or path")
				}
				b, _ := io.ReadAll(r.Body)
				if len(b) > errorUploadBytes || errlog.ContainsSecret(string(b)) || bytes.Contains(b, []byte("opaque")) || bytes.Contains(b, []byte("hidden-value")) {
					t.Error("batch size or redaction")
				}
				var records []errlog.Record
				if err := json.Unmarshal(b, &records); err != nil {
					t.Error(err)
				}
				if len(records) > 200 {
					t.Error("record limit exceeded")
				}
				for _, record := range records {
					if record.MachineID != "machine" || record.Fingerprint != errlog.Fingerprint(record.Component, record.Code, record.Msg) {
						t.Error("incorrect identity")
					}
				}
				total += len(records)
				w.WriteHeader(204)
			})
			var source []byte
			for i := 0; i < 450; i++ {
				source = append(source, uploadRecord(i, "token=private "+strings.Repeat("x", length))...)
			}
			writeUpload(t, path, source)
			mustUpload(t, u)
			if total != 450 || calls < 3 {
				t.Fatalf("total=%d calls=%d", total, calls)
			}
			before, _ := os.ReadFile(path)
			if !bytes.Equal(before, source) {
				t.Fatal("source changed")
			}
			restarted, err := newErrorUploader(u.cfg, u.stateFile)
			if err != nil {
				t.Fatal(err)
			}
			mustUpload(t, restarted)
			if total != 450 {
				t.Fatal("cursor replayed completed records")
			}
		})
	}
}

func TestErrorUploadRotationTruncationAndPartialLine(t *testing.T) {
	var messages []string
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		_ = json.NewDecoder(r.Body).Decode(&records)
		for _, record := range records {
			messages = append(messages, record.Msg)
		}
		w.WriteHeader(204)
	})
	writeUpload(t, path, uploadRecord(0, "first"))
	mustUpload(t, u)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(uploadRecord(1, "rotated tail"))
	_ = f.Close()
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	writeUpload(t, path, uploadRecord(2, "active"))
	mustUpload(t, u)
	// Copy-truncation followed by regrowth past the old offset must reset too.
	writeUpload(t, path, uploadRecord(3, strings.Repeat("replacement", 100)))
	mustUpload(t, u)
	writeUpload(t, path, uploadRecord(4, "short"))
	mustUpload(t, u)
	partial := uploadRecord(5, "partial")
	writeUpload(t, path, partial[:len(partial)-1])
	mustUpload(t, u)
	if len(messages) != 5 {
		t.Fatalf("messages before newline=%v", messages)
	}
	f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString("\n")
	_ = f.Close()
	mustUpload(t, u)
	if len(messages) != 6 || messages[0] != "first" || messages[1] != "rotated tail" || messages[2] != "active" || messages[4] != "short" || messages[5] != "partial" {
		t.Fatalf("messages=%v", messages)
	}
}

func TestErrorUpload404BackoffPersists(t *testing.T) {
	calls := 0
	status := 404
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) })
	now := time.Now()
	u.now = func() time.Time { return now }
	writeUpload(t, path, uploadRecord(0, "pending"))
	if err := u.upload(context.Background()); err == nil {
		t.Fatal("expected 404")
	}
	restarted, err := newErrorUploader(u.cfg, u.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = u.now
	now = now.Add(59 * time.Minute)
	mustUpload(t, restarted)
	if calls != 1 {
		t.Fatal("request during backoff")
	}
	status = 204
	now = now.Add(time.Minute)
	mustUpload(t, restarted)
	if calls != 2 {
		t.Fatal("did not resume")
	}
	mustUpload(t, restarted)
	if calls != 2 {
		t.Fatal("cursor not saved")
	}
}

func TestErrorUploadFailedBatchRetainsCursor(t *testing.T) {
	calls := 0
	status := 400
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) })
	writeUpload(t, path, uploadRecord(0, "pending"))
	if err := u.upload(context.Background()); err == nil {
		t.Fatal("expected failure")
	}
	status = 204
	mustUpload(t, u)
	mustUpload(t, u)
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestErrorUploadOversizeAndInvalidLines(t *testing.T) {
	total := 0
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		_ = json.NewDecoder(r.Body).Decode(&records)
		total += len(records)
		w.WriteHeader(204)
	})
	source := append([]byte(strings.Repeat("x", errorUploadBytes*2)+"\ninvalid\n{}\n"), uploadRecord(0, "valid")...)
	writeUpload(t, path, source)
	mustUpload(t, u)
	mustUpload(t, u)
	if total != 1 {
		t.Fatalf("records=%d", total)
	}
}

func TestErrorUploadPathsAndDisabled(t *testing.T) {
	t.Setenv("AI_INTUNE_ERROR_LOG", "agent.jsonl")
	t.Setenv("AI_INTUNE_BAT_ERROR_LOGS", " /one/errors.jsonl, /two/errors.jsonl, /one/errors.jsonl ")
	paths := errorUploadPaths(config{BATErrorLogs: []string{"ignored"}})
	if strings.Join(paths, ",") != "agent.jsonl,/one/errors.jsonl,/two/errors.jsonl" {
		t.Fatalf("paths=%v", paths)
	}
	t.Setenv("AI_INTUNE_ERROR_UPLOAD", "off")
	runErrorUploads(context.Background(), config{})
}

type errorUploadTransport func(*http.Request) (*http.Response, error)

func (f errorUploadTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestErrorUploadFastRetryFreezesBatch(t *testing.T) {
	calls := 0
	var first []byte
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		b, _ := io.ReadAll(r.Body)
		if calls == 1 {
			first = b
			w.WriteHeader(503)
			return
		}
		if !bytes.Equal(first, b) {
			t.Error("retry payload changed")
		}
		w.WriteHeader(204)
	})
	previous := hubRetries
	t.Cleanup(func() { hubRetries = previous })
	hubRetries = hubRetryPolicy{now: time.Now, sleep: func(context.Context, time.Duration) error { return nil }, delay: func(int) time.Duration { return 0 }}
	writeUpload(t, path, uploadRecord(0, "pending"))
	mustUpload(t, u)
	if calls != 2 {
		t.Fatalf("calls=%d", calls)
	}
}

func TestErrorUploadMultipleBATLogs(t *testing.T) {
	total := 0
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		_ = json.NewDecoder(r.Body).Decode(&records)
		total += len(records)
		w.WriteHeader(204)
	})
	bat1 := filepath.Join(filepath.Dir(path), "bat-one.jsonl")
	bat2 := filepath.Join(filepath.Dir(path), "bat-two.jsonl")
	t.Setenv("AI_INTUNE_BAT_ERROR_LOGS", bat1+","+bat2)
	u.paths = errorUploadPaths(u.cfg)
	writeUpload(t, path, uploadRecord(0, "agent"))
	writeUpload(t, bat1+".2", uploadRecord(1, "bat rotated"))
	writeUpload(t, bat2, uploadRecord(2, "bat active"))
	mustUpload(t, u)
	mustUpload(t, u)
	if total != 3 {
		t.Fatalf("records=%d", total)
	}
}
