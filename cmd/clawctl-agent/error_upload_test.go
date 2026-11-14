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

func TestErrorUploadBusySourceDoesNotStarveBAT(t *testing.T) {
	seenBAT := false
	total := 0
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
			t.Error(err)
		}
		for _, record := range records {
			seenBAT = seenBAT || record.Msg == "bat pending"
		}
		total += len(records)
		w.WriteHeader(http.StatusNoContent)
	})
	bat := filepath.Join(filepath.Dir(path), "bat.jsonl")
	t.Setenv("AI_INTUNE_BAT_ERROR_LOGS", bat)
	u.paths = append(u.paths, bat)
	var source []byte
	for i := 0; i < 20200; i++ {
		source = append(source, uploadRecord(i, "agent pending")...)
	}
	writeUpload(t, path+".1", source)
	writeUpload(t, bat, uploadRecord(0, "bat pending"))
	mustUpload(t, u)
	if !seenBAT {
		t.Fatal("busy agent rotation starved BAT source")
	}
	if total > errorUploadSourceBatches*200+1 {
		t.Fatalf("source exceeded batch allowance: %d records", total)
	}
	for i := 0; i < 11; i++ {
		var err error
		u, err = newErrorUploader(u.cfg, u.stateFile)
		if err != nil {
			t.Fatal(err)
		}
		mustUpload(t, u)
	}
	if total != 20201 {
		t.Fatalf("records after draining across restarts = %d, want 20201", total)
	}
}

func TestErrorUploadCorruptInputBoundedAcrossRestart(t *testing.T) {
	total := 0
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
			t.Error(err)
		}
		total += len(records)
		w.WriteHeader(http.StatusNoContent)
	})
	// The valid-looking suffix belongs to the oversized line and must never
	// become a standalone record when a pass resumes in the middle of it.
	const scanLimit = 4 << 20
	source := bytes.Repeat([]byte("x"), scanLimit*2)
	source = append(source, uploadRecord(0, "oversized suffix")...)
	source = append(source, uploadRecord(1, "valid")...)
	writeUpload(t, path, source)
	mustUpload(t, u)
	if total != 0 {
		t.Fatal("pass read beyond its source byte budget")
	}
	for _, c := range u.state.Cursors {
		if c.Offset == 0 || c.Offset > scanLimit {
			t.Fatalf("bounded scan made incorrect progress: %d", c.Offset)
		}
	}
	for i := 0; i < 3; i++ {
		var err error
		u, err = newErrorUploader(u.cfg, u.stateFile)
		if err != nil {
			t.Fatal(err)
		}
		mustUpload(t, u)
	}
	if total != 1 {
		t.Fatalf("records after restart = %d, want 1", total)
	}
	// The discard state ends with the oversized line: a record appended
	// afterwards is an ordinary record.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write(uploadRecord(2, "after oversized line")); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	u, err = newErrorUploader(u.cfg, u.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	mustUpload(t, u)
	if total != 2 {
		t.Fatalf("records after the oversized line ended = %d, want 2", total)
	}
}

func TestErrorUploadAllowanceIsPerSource(t *testing.T) {
	counts := map[string]int{}
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
			t.Error(err)
		}
		for _, record := range records {
			counts[record.Msg]++
		}
		w.WriteHeader(http.StatusNoContent)
	})
	bat := filepath.Join(filepath.Dir(path), "bat.jsonl")
	u.paths = append(u.paths, bat)
	var agentLog, batLog []byte
	for i := 0; i < errorUploadSourceBatches*200+500; i++ {
		agentLog = append(agentLog, uploadRecord(i, "agent pending")...)
		batLog = append(batLog, uploadRecord(i, "bat pending")...)
	}
	writeUpload(t, path, agentLog)
	writeUpload(t, bat, batLog)
	mustUpload(t, u)
	// One pass gives each busy source its own ten batches of 200 records.
	want := errorUploadSourceBatches * 200
	if counts["agent pending"] != want || counts["bat pending"] != want {
		t.Fatalf("records per source after one pass = %v, want %d each", counts, want)
	}
}

func TestErrorUploadByteBoundaryRetainsPartialRecord(t *testing.T) {
	total := 0
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		var records []errlog.Record
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
			t.Error(err)
		}
		total += len(records)
		w.WriteHeader(http.StatusNoContent)
	})
	record := uploadRecord(0, "crosses scan boundary")
	prefix := bytes.Repeat([]byte("x"), errorUploadSourceBytes-len(record)/2)
	prefix[len(prefix)-1] = '\n'
	writeUpload(t, path, append(prefix, record...))
	mustUpload(t, u)
	if total != 0 {
		t.Fatal("partial record uploaded")
	}
	restarted, err := newErrorUploader(u.cfg, u.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	mustUpload(t, restarted)
	mustUpload(t, restarted)
	if total != 1 {
		t.Fatalf("records = %d, want 1", total)
	}
}

func TestErrorUploadDiscardProgressRequiresAcknowledgment(t *testing.T) {
	status, calls := http.StatusBadRequest, 0
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		var records []errlog.Record
		if err := json.NewDecoder(r.Body).Decode(&records); err != nil {
			t.Error(err)
		}
		if len(records) != 1 || records[0].Msg != "pending" {
			t.Errorf("unexpected batch: %+v", records)
		}
		w.WriteHeader(status)
	})
	source := append(uploadRecord(0, "pending"), bytes.Repeat([]byte("x"), errorUploadSourceBytes*2)...)
	writeUpload(t, path, source)
	if err := u.upload(context.Background()); err == nil {
		t.Fatal("expected rejected batch")
	}
	if len(u.state.Cursors) != 0 {
		t.Fatal("discard checkpoint skipped unacknowledged record")
	}
	restarted, err := newErrorUploader(u.cfg, u.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	status = http.StatusNoContent
	mustUpload(t, restarted)
	mustUpload(t, restarted)
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	// A copy-truncated file must not inherit the oversized-line discard state.
	writeUpload(t, path, uploadRecord(1, "pending"))
	mustUpload(t, restarted)
	if calls != 3 {
		t.Fatal("truncation retained discard state")
	}
}

func TestErrorUploadCancellationRetainsUnacknowledgedCursor(t *testing.T) {
	u, path := uploadFixture(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	entered := make(chan struct{})
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		close(entered)
		<-release
	}))
	defer server.Close()
	defer close(release)
	u.cfg.HubURL = server.URL
	httpClient = server.Client()
	writeUpload(t, path, uploadRecord(0, "pending"))
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go func() {
		select {
		case <-entered:
			cancel()
		case <-ctx.Done():
		}
	}()
	if err := u.upload(ctx); err == nil {
		t.Fatal("expected cancellation")
	}
	if ctx.Err() != context.Canceled {
		t.Fatalf("request failed to reach local server: %v", ctx.Err())
	}
	if len(u.state.Cursors) != 0 {
		t.Fatal("cancellation advanced cursor without acknowledgment")
	}
	restarted, err := newErrorUploader(u.cfg, u.stateFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(restarted.state.Cursors) != 0 {
		t.Fatal("restart skipped canceled batch")
	}
}
