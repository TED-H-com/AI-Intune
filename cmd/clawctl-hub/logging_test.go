package main

import (
	"bufio"
	"bytes"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type loggingHijackRecorder struct {
	*httptest.ResponseRecorder
	conn net.Conn
}

func (w *loggingHijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestLoggingResponseSemantics(t *testing.T) {
	oldLogger := slog.Default()
	t.Cleanup(func() { slog.SetDefault(oldLogger) })
	for _, tc := range []struct {
		name   string
		status string
		serve  func(http.ResponseWriter)
	}{
		{"implicit body", `"status":200`, func(w http.ResponseWriter) {
			_, _ = w.Write([]byte("body"))
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"first final status", `"status":201`, func(w http.ResponseWriter) {
			w.WriteHeader(http.StatusEarlyHints)
			w.WriteHeader(http.StatusCreated)
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"stream flush", `"status":200`, func(w http.ResponseWriter) {
			w.(http.Flusher).Flush()
			w.WriteHeader(http.StatusInternalServerError)
		}},
		{"terminal upgrade", `"status":101`, func(w http.ResponseWriter) {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Fatal(err)
			}
			_ = conn.Close()
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
			conn, peer := net.Pipe()
			defer conn.Close()
			defer peer.Close()
			recorder := &loggingHijackRecorder{httptest.NewRecorder(), conn}
			handler := newLoggingMiddleware(1000, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { tc.serve(w) }))
			handler.ServeHTTP(recorder, httptest.NewRequest("GET", "/", nil))
			if !strings.Contains(buf.String(), tc.status) {
				t.Fatalf("expected %s in %s", tc.status, buf.String())
			}
		})
	}
}

func TestLoggingMiddleware(t *testing.T) {
	oldLogger := slog.Default()
	defer slog.SetDefault(oldLogger)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})
	slog.SetDefault(slog.New(handler))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /machines/{id}", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	mux.HandleFunc("GET /slow", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("Fast Request with Route Pattern", func(t *testing.T) {
		buf.Reset()

		var mockTime time.Time
		nowFunc := func() time.Time {
			ret := mockTime
			mockTime = mockTime.Add(10 * time.Millisecond) // duration = 10ms
			return ret
		}

		loggedMux := newLoggingMiddleware(100, nowFunc)(mux)

		req := httptest.NewRequest("GET", "/machines/abc", nil)
		rr := httptest.NewRecorder()
		loggedMux.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("Expected 201, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, `"msg":"request"`) {
			t.Errorf("Expected info log message, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"level":"INFO"`) {
			t.Errorf("Expected level INFO in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"route":"GET /machines/{id}"`) {
			t.Errorf("Expected route GET /machines/{id} in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"status":201`) {
			t.Errorf("Expected status 201 in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"duration_ms":10`) {
			t.Errorf("Expected duration_ms:10 in log, got: %s", logOutput)
		}
	})

	t.Run("Slow Request Deterministic", func(t *testing.T) {
		buf.Reset()

		var mockTime time.Time
		nowFunc := func() time.Time {
			ret := mockTime
			mockTime = mockTime.Add(150 * time.Millisecond) // duration = 150ms
			return ret
		}

		loggedMux := newLoggingMiddleware(100, nowFunc)(mux)

		req := httptest.NewRequest("GET", "/slow", nil)
		rr := httptest.NewRecorder()
		loggedMux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, `"msg":"slow request"`) {
			t.Errorf("Expected warn log message, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"level":"WARN"`) {
			t.Errorf("Expected level WARN in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"route":"GET /slow"`) {
			t.Errorf("Expected route GET /slow in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"status":200`) {
			t.Errorf("Expected status 200 in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"duration_ms":150`) {
			t.Errorf("Expected duration_ms:150 in log, got: %s", logOutput)
		}
	})

	t.Run("Unmatched Route", func(t *testing.T) {
		buf.Reset()

		var mockTime time.Time
		nowFunc := func() time.Time {
			ret := mockTime
			mockTime = mockTime.Add(5 * time.Millisecond) // duration = 5ms
			return ret
		}

		loggedMux := newLoggingMiddleware(100, nowFunc)(mux)

		req := httptest.NewRequest("GET", "/does-not-exist", nil)
		rr := httptest.NewRecorder()
		loggedMux.ServeHTTP(rr, req)

		if rr.Code != http.StatusNotFound {
			t.Errorf("Expected 404, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, `"route":"unmatched"`) {
			t.Errorf("Expected route unmatched in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"status":404`) {
			t.Errorf("Expected status 404 in log, got: %s", logOutput)
		}
	})
}

func TestParseThreshold(t *testing.T) {
	oldLogger := slog.Default()
	defer slog.SetDefault(oldLogger)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	slog.SetDefault(slog.New(handler))

	t.Run("Valid", func(t *testing.T) {
		buf.Reset()
		if v := parseThreshold("500"); v != 500 {
			t.Errorf("expected 500, got %d", v)
		}
		if buf.Len() > 0 {
			t.Errorf("expected no warning log, got %s", buf.String())
		}
	})

	t.Run("Empty", func(t *testing.T) {
		buf.Reset()
		if v := parseThreshold(""); v != 1000 {
			t.Errorf("expected 1000, got %d", v)
		}
		if buf.Len() > 0 {
			t.Errorf("expected no warning log, got %s", buf.String())
		}
	})

	t.Run("Invalid Format", func(t *testing.T) {
		buf.Reset()
		if v := parseThreshold("abc"); v != 1000 {
			t.Errorf("expected 1000, got %d", v)
		}
		if !strings.Contains(buf.String(), "invalid CLAWCTL_SLOW_REQUEST_MS") {
			t.Errorf("expected warning log, got %s", buf.String())
		}
	})

	t.Run("Invalid Negative", func(t *testing.T) {
		buf.Reset()
		if v := parseThreshold("-50"); v != 1000 {
			t.Errorf("expected 1000, got %d", v)
		}
		if !strings.Contains(buf.String(), "invalid CLAWCTL_SLOW_REQUEST_MS") {
			t.Errorf("expected warning log, got %s", buf.String())
		}
	})
}
