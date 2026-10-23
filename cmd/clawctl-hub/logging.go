package main

import (
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"
)

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *loggingResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *loggingResponseWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		w.ResponseWriter.WriteHeader(status)
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func loggingMiddleware(next http.Handler) http.Handler {
	thresholdStr := os.Getenv("CLAWCTL_SLOW_REQUEST_MS")
	threshold := 1000
	if thresholdStr != "" {
		if val, err := strconv.Atoi(thresholdStr); err == nil && val > 0 {
			threshold = val
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		lw := &loggingResponseWriter{ResponseWriter: w, status: 0}

		defer func() {
			duration := time.Since(start)
			durationMs := duration.Milliseconds()

			if lw.status == 0 {
				lw.status = http.StatusOK
			}

			route := r.Pattern
			if route == "" {
				// fallback if pattern not available
				route = r.URL.Path
			}

			if durationMs > int64(threshold) {
				slog.Warn("slow request",
					slog.String("method", r.Method),
					slog.String("route", route),
					slog.Int("status", lw.status),
					slog.Int64("duration_ms", durationMs),
				)
			} else {
				slog.Info("request",
					slog.String("method", r.Method),
					slog.String("route", route),
					slog.Int("status", lw.status),
					slog.Int64("duration_ms", durationMs),
				)
			}
		}()

		next.ServeHTTP(lw, r)
	})
}
