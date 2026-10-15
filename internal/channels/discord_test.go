package channels

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

func TestDiscordSendAndHealth(t *testing.T) {
	const token = "discord-secret-canary"
	t.Setenv("DISCORD_TEST_TOKEN", token)
	t.Setenv("DISCORD_TEST_CHANNEL", "123456")
	for _, webhook := range []bool{false, true} {
		t.Run(fmt.Sprint(webhook), func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				expected := "/users/@me"
				if r.Method == http.MethodPost {
					expected = "/channels/123456/messages"
				}
				if webhook {
					expected = "/webhooks/123/" + token
				}
				if r.URL.Path != expected {
					t.Error("incorrect endpoint")
				}
				if !webhook && r.Header.Get("Authorization") != "Bot "+token {
					t.Error("missing bot authorization")
				}
				if webhook && r.Header.Get("Authorization") != "" {
					t.Error("unexpected authorization")
				}
				if r.Method == http.MethodPost {
					var payload struct {
						Content         string
						AllowedMentions struct{ Parse []string } `json:"allowed_mentions"`
					}
					if json.NewDecoder(r.Body).Decode(&payload) != nil || payload.Content != "hello" || payload.AllowedMentions.Parse == nil || len(payload.AllowedMentions.Parse) != 0 {
						t.Error("incorrect payload")
					}
					w.WriteHeader(204)
				} else {
					io.WriteString(w, `{"id":"123","bot":true}`)
				}
			}))
			t.Setenv("DISCORD_TEST_URL", srv.URL+"/webhooks/123/"+token)
			c := Config{TokenRef: "env://DISCORD_TEST_TOKEN", ChatRef: "env://DISCORD_TEST_CHANNEL"}
			if webhook {
				c = Config{URLRef: "env://DISCORD_TEST_URL"}
			}
			p := NewDiscordForAPI(c, secrets.New(nil), srv.URL)
			if status, e := p.Health(context.Background()); e != nil || status != Ready {
				t.Fatal(status, e)
			}
			if e := p.Send(context.Background(), Message{Text: "hello"}); e != nil {
				t.Fatal(e)
			}
			if calls != 2 {
				t.Fatal(calls)
			}
			raw, _ := json.Marshal(p)
			if strings.Contains(string(raw)+fmt.Sprintf("%v %#v", p, p), token) {
				t.Fatal("provider leaked secret")
			}
			srv.Close()
			for _, run := range []func() error{func() error { return p.Send(context.Background(), Message{Text: "hello"}) }, func() error { _, e := p.Health(context.Background()); return e }} {
				if e := run(); e == nil || strings.Contains(e.Error(), token) || strings.Contains(e.Error(), "/webhooks/") {
					t.Fatal("unsafe transport error")
				}
			}
		})
	}
}

func TestDiscordRateLimits(t *testing.T) {
	for _, header := range []bool{true, false} {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if calls == 1 {
				if header {
					w.Header().Set("Retry-After", "0.03")
				}
				w.WriteHeader(429)
				io.WriteString(w, `{"retry_after":0.03}`)
				return
			}
			w.WriteHeader(204)
		}))
		t.Setenv("DISCORD_RATE_URL", srv.URL+"/webhooks/1/secret")
		p := NewDiscord(Config{URLRef: "env://DISCORD_RATE_URL"}, secrets.New(nil))
		start := time.Now()
		if e := p.Send(context.Background(), Message{Text: "hello"}); e != nil {
			t.Fatal(e)
		}
		if calls != 2 || time.Since(start) < 30*time.Millisecond {
			t.Fatal("retry delay ignored")
		}
		srv.Close()
	}
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(429)
		io.WriteString(w, `{"retry_after":0}`)
	}))
	defer srv.Close()
	t.Setenv("DISCORD_RATE_URL", srv.URL)
	p := NewDiscord(Config{URLRef: "env://DISCORD_RATE_URL"}, secrets.New(nil))
	if e := p.Send(context.Background(), Message{Text: "hello"}); e == nil || calls != discordRetries+1 {
		t.Fatal("retry bound", calls, e)
	}
	if status, e := p.Health(context.Background()); e == nil || status != Unavailable {
		t.Fatal("health accepted rate limit")
	}
	if discordRetryDelay("100000", nil) != discordMaxWait {
		t.Fatal("unbounded delay")
	}
	if discordRetryDelay("", []byte(`{"retry_after":100000}`)) != discordMaxWait {
		t.Fatal("unbounded JSON delay")
	}
}
func TestDiscordRetryCancellationAndFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "10")
		w.WriteHeader(429)
	}))
	defer srv.Close()
	t.Setenv("DISCORD_CANCEL_URL", srv.URL)
	p := NewDiscord(Config{URLRef: "env://DISCORD_CANCEL_URL"}, secrets.New(nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	if e := p.Send(ctx, Message{Text: "hello"}); e == nil || time.Since(start) > time.Second {
		t.Fatal("cancellation ignored")
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		io.WriteString(w, "secret-path-token")
	}))
	defer bad.Close()
	t.Setenv("DISCORD_CANCEL_URL", bad.URL+"/secret-path-token")
	if status, e := p.Health(context.Background()); status != Unavailable || e == nil || strings.Contains(e.Error(), "secret-path-token") {
		t.Fatal("unsafe health failure")
	}
}
