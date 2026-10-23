package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoggingMiddleware(t *testing.T) {
	oldLogger := slog.Default()
	defer slog.SetDefault(oldLogger)

	var buf bytes.Buffer
	handler := slog.NewJSONHandler(&buf, nil)
	slog.SetDefault(slog.New(handler))

	mux := http.NewServeMux()
	mux.HandleFunc("/test", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
	})

	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(1500 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	})

	loggedMux := loggingMiddleware(mux)

	t.Run("Fast Request", func(t *testing.T) {
		buf.Reset()
		req := httptest.NewRequest("GET", "/test", nil)
		rr := httptest.NewRecorder()
		loggedMux.ServeHTTP(rr, req)

		if rr.Code != http.StatusCreated {
			t.Errorf("Expected 201, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, `"msg":"request"`) {
			t.Errorf("Expected info log message, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"method":"GET"`) {
			t.Errorf("Expected method GET in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"status":201`) {
			t.Errorf("Expected status 201 in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"duration_ms":`) {
			t.Errorf("Expected duration_ms in log, got: %s", logOutput)
		}
	})

	t.Run("Slow Request", func(t *testing.T) {
		t.Setenv("CLAWCTL_SLOW_REQUEST_MS", "100")

		buf.Reset()
		req := httptest.NewRequest("GET", "/slow", nil)
		rr := httptest.NewRecorder()

		// Create a new middleware instance to pick up the env var
		loggedMux = loggingMiddleware(mux)
		loggedMux.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Errorf("Expected 200, got %d", rr.Code)
		}

		logOutput := buf.String()
		if !strings.Contains(logOutput, `"msg":"slow request"`) {
			t.Errorf("Expected warn log message, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"method":"GET"`) {
			t.Errorf("Expected method GET in log, got: %s", logOutput)
		}
		if !strings.Contains(logOutput, `"status":200`) {
			t.Errorf("Expected status 200 in log, got: %s", logOutput)
		}
	})
}
