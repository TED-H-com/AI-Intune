package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHubFastRetry(t *testing.T) {
	for _, mode := range []string{"reset", "EOF", "502", "503", "504", "429", "400", "401", "403", "404"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			var bodies []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				b, _ := io.ReadAll(r.Body)
				bodies = append(bodies, string(b))
				if calls == 1 {
					switch mode {
					case "reset":
						conn, _, _ := w.(http.Hijacker).Hijack()
						conn.Close()
						return
					case "EOF":
						w.Header().Set("Content-Length", "100")
						io.WriteString(w, `{"ok":`)
						return
					default:
						code := 0
						for _, c := range mode {
							code = code*10 + int(c-'0')
						}
						w.WriteHeader(code)
						return
					}
				}
				io.WriteString(w, `{"ok":true}`)
			}))
			defer server.Close()
			now := time.Now()
			sleeps := 0
			p := hubRetryPolicy{func() time.Time { return now }, func(_ context.Context, d time.Duration) error { sleeps++; now = now.Add(d); return nil }, func(int) time.Duration { return time.Second }}
			var out map[string]any
			_, err := p.do(context.Background(), "POST", server.URL+"/v1/checkins", "secret", map[string]int{"seq": 1}, &out, false)
			want := 2
			if strings.HasPrefix(mode, "4") && mode != "429" {
				want = 1
			}
			if calls != want || sleeps != want-1 {
				t.Fatalf("calls=%d sleeps=%d", calls, sleeps)
			}
			if want == 2 && err != nil {
				t.Fatal(err)
			}
			if want == 1 && err == nil {
				t.Fatal("expected HTTP error")
			}
			for _, b := range bodies {
				if b != `{"seq":1}` {
					t.Fatalf("body=%q", b)
				}
			}
		})
	}
}

func TestHubRetryAfterAndBudget(t *testing.T) {
	for _, tc := range []struct {
		name      string
		header    string
		interval  time.Duration
		delay     time.Duration
		wantCalls int
		wantSleep time.Duration
	}{
		{"seconds", "3", 80 * time.Second, time.Second, 4, 9 * time.Second},
		{"date", time.Now().Add(3 * time.Second).UTC().Format(http.TimeFormat), 80 * time.Second, time.Second, 4, -1},
		{"server delay exceeds cap", "120", 10 * time.Minute, time.Second, 1, 0},
		{"default poll interval allows retries", "3", 30 * time.Second, time.Second, 4, 9 * time.Second},
		{"retry after equals remaining budget", "3", 8 * time.Second, time.Second, 2, 3 * time.Second},
		{"retry after exceeds budget", "23", 30 * time.Second, time.Second, 1, 0},
		{"backoff equals budget", "", 30 * time.Second, 22500 * time.Millisecond, 1, 0},
		{"backoff exceeds remaining budget", "", 30 * time.Second, 8 * time.Second, 3, 16 * time.Second},
	} {
		t.Run(tc.name, func(t *testing.T) {
			header := tc.header
			now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				w.Header().Set("Retry-After", header)
				w.WriteHeader(503)
			}))
			defer server.Close()
			total := time.Duration(0)
			p := hubRetryPolicy{func() time.Time { return now }, func(_ context.Context, d time.Duration) error { total += d; now = now.Add(d); return nil }, func(int) time.Duration { return tc.delay }}
			_, err := p.do(withHubRetryInterval(context.Background(), tc.interval), "GET", server.URL+"/v1/jobs/next", "", nil, nil, false)
			if err == nil {
				t.Fatal("expected error")
			}
			if calls != tc.wantCalls {
				t.Fatalf("calls=%d want=%d delay=%s", calls, tc.wantCalls, total)
			}
			if tc.wantSleep >= 0 {
				if total != tc.wantSleep {
					t.Fatalf("sleep=%s want=%s", total, tc.wantSleep)
				}
			} else if total < 6*time.Second || total > 9*time.Second {
				t.Fatalf("Retry-After delay=%s", total)
			}
		})
	}
}

func TestHubRetrySafety(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(502) }))
	defer server.Close()
	p := hubRetryPolicy{time.Now, func(context.Context, time.Duration) error { t.Fatal("unsafe retry"); return nil }, func(int) time.Duration { return 0 }}
	for _, path := range []string{"/v1/enroll", "/v1/observations:batch", "/v1/jobs/id/lease", "/v1/jobs/id/events"} {
		_, _ = p.do(context.Background(), "POST", server.URL+path, "", nil, nil, false)
	}
	if calls != 4 {
		t.Fatal(calls)
	}
}

func TestHubRetryDeadline(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		<-r.Context().Done()
	}))
	defer server.Close()
	p := hubRetryPolicy{time.Now, hubRetrySleep, func(int) time.Duration { return time.Second }}
	start := time.Now()
	_, err := p.do(withHubRetryInterval(context.Background(), 50*time.Millisecond), "POST", server.URL+"/v1/checkins", "", nil, nil, false)
	if err == nil || calls != 1 || time.Since(start) > time.Second {
		t.Fatalf("calls=%d elapsed=%s err=%v", calls, time.Since(start), err)
	}
}

func TestHubRetryReasons(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{io.EOF, "EOF"}, {io.ErrUnexpectedEOF, "EOF"},
		{context.DeadlineExceeded, "timeout"}, {context.Canceled, ""},
		{&hubHTTPError{StatusCode: 502}, "HTTP_502"},
		{&hubHTTPError{StatusCode: 408}, ""},
		{&hubHTTPError{StatusCode: 500}, ""},
	} {
		if got := hubRetryReason(tc.err); got != tc.want {
			t.Fatalf("reason=%q want=%q", got, tc.want)
		}
	}
}

func TestHubRetryTransientSequence(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		switch calls {
		case 1:
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = conn.Close()
		case 2:
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, `{"ok":`)
		case 3:
			w.WriteHeader(http.StatusBadGateway)
		default:
			_, _ = io.WriteString(w, `{"ok":true}`)
		}
	}))
	defer server.Close()
	now := time.Now()
	var slept time.Duration
	p := hubRetryPolicy{
		func() time.Time { return now },
		func(_ context.Context, d time.Duration) error {
			slept += d
			now = now.Add(d)
			return nil
		},
		func(int) time.Duration { return time.Second },
	}
	var out map[string]bool
	_, err := p.do(context.Background(), http.MethodPost, server.URL+"/v1/checkins", "", nil, &out, false)
	if err != nil || calls != 4 || slept != 3*time.Second || !out["ok"] {
		t.Fatalf("calls=%d sleep=%s out=%v err=%v", calls, slept, out, err)
	}
}

// A retry may use the remaining budget even when less than a full request
// timeout remains. The shared context must still stop a hanging final attempt.
func TestHubRetryFinalAttemptBoundedByBudget(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		<-r.Context().Done()
	}))
	defer server.Close()

	const interval = 400 * time.Millisecond
	const budget = interval * 3 / 4
	var deadline time.Time
	p := hubRetryPolicy{
		time.Now,
		func(ctx context.Context, delay time.Duration) error {
			deadline, _ = ctx.Deadline()
			return hubRetrySleep(ctx, delay)
		},
		func(int) time.Duration { return 10 * time.Millisecond },
	}
	start := time.Now()
	_, err := p.do(withHubRetryInterval(context.Background(), interval), http.MethodGet, server.URL+"/v1/jobs/next", "", nil, nil, false)
	elapsed := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "context deadline exceeded") || calls != 2 {
		t.Fatalf("calls=%d elapsed=%s err=%v", calls, elapsed, err)
	}
	if deadline.IsZero() || deadline.Sub(start) > budget+10*time.Millisecond {
		t.Fatalf("deadline=%s want budget=%s", deadline.Sub(start), budget)
	}
	if elapsed < budget || elapsed > budget+200*time.Millisecond {
		t.Fatalf("elapsed=%s want budget=%s", elapsed, budget)
	}
}
