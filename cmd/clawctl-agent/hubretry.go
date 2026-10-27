package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"
)

type hubRetryIntervalKey struct{}

func withHubRetryInterval(ctx context.Context, interval time.Duration) context.Context {
	return context.WithValue(ctx, hubRetryIntervalKey{}, interval)
}

// Only these protocol operations are safe to replay. Job mutations and
// enrollment retain their existing behavior and never enter this retry loop.
// Check-ins upsert by (machine_id, sent_at). Observation uploads append new
// history IDs on every submission, so they are deliberately excluded.
func fastRetrySafe(method, path string) bool {
	return method == http.MethodGet && (path == "/v1/jobs/next" || path == "/v1/agent/readiness") ||
		method == http.MethodPost && path == "/v1/checkins"
}

type hubRetryPolicy struct {
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
	delay func(int) time.Duration
}

var hubRetries = hubRetryPolicy{time.Now, hubRetrySleep, func(attempt int) time.Duration {
	base := []time.Duration{1500 * time.Millisecond, 5 * time.Second, 15 * time.Second}[attempt-1]
	return base + fullJitter(base/5)
}}

func doJSONStatusMode(ctx context.Context, method, endpoint, token string, body, out any, strict bool) (int, error) {
	return hubRetries.do(ctx, method, endpoint, token, body, out, strict)
}

func (p hubRetryPolicy) do(ctx context.Context, method, endpoint, token string, body, out any, strict bool) (int, error) {
	u, err := url.Parse(endpoint)
	if err != nil || p.delay == nil || !fastRetrySafe(method, u.Path) {
		return doJSONStatusOnce(ctx, method, endpoint, token, body, out, strict)
	}
	// Freeze the payload once; each attempt gets a fresh bytes.Reader/GetBody.
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		body = json.RawMessage(raw)
	}
	budget := 60 * time.Second
	if interval, ok := ctx.Value(hubRetryIntervalKey{}).(time.Duration); ok && interval > 0 {
		budget = min(budget, interval/4*3)
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	started := p.now()
	var status int
	for attempt := 1; ; attempt++ {
		status, err = doJSONStatusOnce(ctx, method, endpoint, token, body, out, strict)
		reason := hubRetryReason(err)
		if err == nil || reason == "" || attempt > 3 || ctx.Err() != nil {
			return status, err
		}
		delay := p.delay(attempt)
		if ra := honoredRetryAfter(err); ra > delay {
			delay = ra
		}
		// Never start a retry whose backoff alone would exceed the budget; the
		// budget context bounds the final attempt so the total stays under one
		// interval even when a request hangs.
		if p.now().Sub(started)+delay >= budget {
			return status, err
		}
		log.Printf("hub retry method=%s path=%s attempt=%d reason=%s delay=%s", method, u.Path, attempt+1, reason, delay)
		if err := p.sleep(ctx, delay); err != nil {
			return status, err
		}
	}
}

func hubRetryReason(err error) string {
	if err == nil {
		return ""
	}
	var h *hubHTTPError
	if errors.As(err, &h) {
		switch h.StatusCode {
		case 429:
			return "HTTP_429"
		case 502:
			return "HTTP_502"
		case 503:
			return "HTTP_503"
		case 504:
			return "HTTP_504"
		}
		return ""
	}
	var n net.Error
	if errors.As(err, &n) && n.Timeout() {
		return "timeout"
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return "EOF"
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.EPIPE) {
		return "connection"
	}
	return ""
}

func hubRetrySleep(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
