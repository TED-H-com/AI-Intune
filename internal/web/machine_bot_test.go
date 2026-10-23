package web

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMachineBotTemplate(t *testing.T) {
	s, _ := newServer(t)
	var out bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&out, "machine_bot.html", page{Title: "Bot view", BotJSON: `{"text":"[REDACTED] <script>"}`}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Bot view", "Back to human detail", "Configure token routes", "[REDACTED]", "&lt;script&gt;"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(out.String(), "<script>") {
		t.Fatal("unescaped JSON")
	}
}

func TestMachineBotViewUsesSafeProjection(t *testing.T) {
	s, st := newServer(t)
	id, _, err := st.CreateEnrollTokenFor("password=fixture-value", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Routes(mux)

	request := func(target string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := verifiedWebRequest(httptest.NewRequest(http.MethodGet, target, nil), "example.com/cap/clawctl-view")
		mux.ServeHTTP(rec, req)
		return rec
	}
	bot := request("/machines/" + id + "?view=bot")
	if bot.Code != http.StatusOK || bot.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("bot status=%d cache=%q", bot.Code, bot.Header().Get("Cache-Control"))
	}
	for _, want := range []string{"Bot view", "[REDACTED]", "redaction_flags", "scrubber_version"} {
		if !strings.Contains(bot.Body.String(), want) {
			t.Fatalf("bot view missing %q", want)
		}
	}
	if strings.Contains(bot.Body.String(), "fixture-value") {
		t.Fatal("bot view leaked scrubbed source text")
	}

	human := request("/machines/" + id)
	if human.Code != http.StatusOK || !strings.Contains(human.Body.String(), "fixture-value") || !strings.Contains(human.Body.String(), "Bot view") {
		t.Fatalf("human detail changed or lacks bot-view link: status=%d", human.Code)
	}
}
