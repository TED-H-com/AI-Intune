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

func parseThreshold(envValue string) int {
	threshold := 1000
	if envValue != "" {
		if val, err := strconv.Atoi(envValue); err == nil && val > 0 {
			threshold = val
		} else {
			slog.Warn("invalid CLAWCTL_SLOW_REQUEST_MS value, falling back to 1000ms", slog.String("value", envValue))
		}
	}
	return threshold
}

// loggingMiddleware configures the middleware logic. It takes optional
// dependency injection functions to make tests deterministic and fast.
func newLoggingMiddleware(threshold int, nowFunc func() time.Time) func(http.Handler) http.Handler {
	if nowFunc == nil {
		nowFunc = time.Now
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := nowFunc()
			lw := &loggingResponseWriter{ResponseWriter: w, status: 0}

			defer func() {
				duration := nowFunc().Sub(start)
				durationMs := duration.Milliseconds()

				if lw.status == 0 {
					lw.status = http.StatusOK
				}

				// Look up the matched pattern AFTER ServeHTTP runs,
				// since ServeMux populates r.Pattern during dispatch.
				// (Requires Go 1.22+)
				route := r.Pattern
				if route == "" {
					route = "unmatched"
				}

				if durationMs > int64(threshold) {
					slog.Warn("slow request",
						slog.String("method", r.Method),
						slog.String("route", route),
						slog.Int("status", lw.status),
						slog.Int64("duration_ms", durationMs),
					)
				} else {
					slog.Debug("request",
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
}

// loggingMiddleware is the standard Hub HTTP server middleware
func loggingMiddleware(next http.Handler) http.Handler {
	threshold := parseThreshold(os.Getenv("CLAWCTL_SLOW_REQUEST_MS"))
	return newLoggingMiddleware(threshold, time.Now)(next)
}
