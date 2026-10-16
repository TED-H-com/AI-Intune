package channels

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/secrets"
)

func TestProviders(t *testing.T) {
	const canary = "canary-channel-secret"
	t.Setenv("CHANNEL_TOKEN", canary)
	t.Setenv("CHANNEL_CHAT", "123")
	t.Setenv("CHANNEL_SIGN", canary)
	for _, kind := range []string{"telegram", "webhook"} {
		t.Run(kind, func(t *testing.T) {
			calls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("User-Agent") != "clawctl-hub" {
					t.Error("user agent")
				}
				if kind == "telegram" {
					if r.URL.Path != "/bot"+canary+"/sendMessage" {
						t.Error("endpoint")
					}
					_ = r.ParseForm()
					if r.FormValue("chat_id") != "123" || r.FormValue("text") != "hello" || r.FormValue("disable_web_page_preview") != "true" {
						t.Error("telegram form")
					}
					_, _ = io.WriteString(w, `{"ok":true}`)
				} else {
					raw, _ := io.ReadAll(r.Body)
					var m map[string]string
					if json.Unmarshal(raw, &m) != nil || m["text"] != "hello" || m["kind"] != "test" || m["sent_at"] == "" {
						t.Error("payload")
					}
					mac := hmac.New(sha256.New, []byte(canary))
					mac.Write(raw)
					if r.Header.Get("X-Clawctl-Signature") != "sha256="+hex.EncodeToString(mac.Sum(nil)) {
						t.Error("signature")
					}
					w.WriteHeader(204)
				}
			}))
			defer srv.Close()
			t.Setenv("CHANNEL_URL", srv.URL)
			c := Config{ID: "test", Kind: kind}
			if kind == "telegram" {
				c.TokenRef = "env://CHANNEL_TOKEN"
				c.ChatRef = "env://CHANNEL_CHAT"
			} else {
				c.URLRef = "env://CHANNEL_URL"
				c.SecretRef = "env://CHANNEL_SIGN"
			}
			p := New(c, secrets.New(nil))
			if kind == "telegram" {
				p = NewTelegramForAPI(c, secrets.New(nil), srv.URL)
			}
			if e := ValidateConfig(c); e != nil {
				t.Fatal(e)
			}
			if status, e := p.Health(context.Background()); e != nil || status != Ready {
				t.Fatal(status, e)
			}
			if calls != 0 {
				t.Fatal("health sent network request")
			}
			if e := p.Send(context.Background(), Message{Kind: "test", Text: "hello"}); e != nil {
				t.Fatal(e)
			}
			raw, _ := json.Marshal(p)
			if strings.Contains(string(raw)+fmt.Sprintf("%v %#v", p, p), canary) {
				t.Fatal("credential leaked")
			}
			if calls != 1 {
				t.Fatal(calls)
			}
		})
	}
}
func TestProviderErrorsDoNotExposeSecrets(t *testing.T) {
	const canary = "channel-error-canary"
	t.Setenv("ERROR_TOKEN", canary)
	t.Setenv("ERROR_CHAT", "chat")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"ok":false,"description":%q}`, canary)
	}))
	defer srv.Close()
	p := NewTelegramForAPI(Config{Kind: "telegram", TokenRef: "env://ERROR_TOKEN", ChatRef: "env://ERROR_CHAT"}, secrets.New(nil), srv.URL)
	e := p.Send(context.Background(), Message{Text: "hello"})
	if e == nil || strings.Contains(e.Error(), canary) {
		t.Fatal("secret in provider error")
	}
	srv.Close()
	if e = p.Send(context.Background(), Message{Text: "hello"}); e == nil || strings.Contains(e.Error(), canary) {
		t.Fatal("secret in transport error")
	}
}

func TestReferenceValidationAndMissingCredentials(t *testing.T) {
	for _, c := range []Config{
		{Kind: "telegram", TokenRef: "raw-token", ChatRef: "env://CHAT"},
		{Kind: "webhook", URLRef: "https://example.invalid/secret"},
		{Kind: "webhook", URLRef: "env://URL", TokenRef: "env://TOKEN"},
		{Kind: "unknown"},
	} {
		if e := ValidateConfig(c); e == nil {
			t.Fatal("accepted invalid configuration")
		}
	}
	t.Setenv("CHANNEL_VALIDATION_URL", "https://example.invalid")
	p := New(Config{Kind: "webhook", URLRef: "env://CHANNEL_VALIDATION_URL", SecretRef: "env://CHANNEL_VALIDATION_MISSING"}, secrets.New(nil))
	if status, e := p.Health(context.Background()); status != Unavailable || e == nil {
		t.Fatal("missing signing credential silently ignored")
	}
	for _, raw := range []string{"http://example.invalid", "file:///tmp/example", "https://", "invalid"} {
		if e := ValidateWebhookURL(raw); e == nil {
			t.Fatal("accepted invalid webhook URL")
		}
	}
}
