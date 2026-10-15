package web

import (
	"bytes"
	"context"
	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/secrets"
	"github.com/teddashh/AI-Intune/internal/store"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestChannelsPermissionsCSRFAndRedaction(t *testing.T) {
	s, st := newServer(t)
	const canary = "channels-web-canary"
	t.Setenv("CHANNEL_WEB_SECRET", canary)
	calls := 0
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(204) }))
	defer target.Close()
	t.Setenv("CHANNEL_WEB_URL", target.URL)
	s.SetSecretProvider(secrets.New(nil))
	c := channels.Config{ID: "example", Kind: "webhook", URLRef: "env://CHANNEL_WEB_URL", SecretRef: "env://CHANNEL_WEB_SECRET"}
	if e := st.MutateChannel(context.Background(), "save", c, "", store.AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	if e := st.UpsertMachine(store.Machine{MachineID: "machine-example", DisplayName: "Example", Expected: true}); e != nil {
		t.Fatal(e)
	}
	names, _ := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	mux := http.NewServeMux()
	s.Routes(mux)
	request := func(method, path, body string, admin, cross bool) *httptest.ResponseRecorder {
		caps := operatorauth.CapabilityNames{View: names.View, Operate: names.Operate}
		if admin {
			caps.Admin = names.Admin
		}
		req := requestWithCapabilities(method, path, caps)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Body = http.NoBody
		if body != "" {
			req.Body = io.NopCloser(strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if cross {
			req.Header.Set("Sec-Fetch-Site", "cross-site")
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if strings.Contains(rec.Body.String(), canary) || strings.Contains(rec.Body.String(), "sentinel-secret-web") {
			t.Fatal("secret returned")
		}
		return rec
	}
	// Neither absent origin evidence nor unauthenticated requests can mutate.
	for _, authenticated := range []bool{true, false} {
		req := httptest.NewRequest("POST", "/channels/bot-remove", strings.NewReader("name=example"))
		if authenticated {
			req = requestWithCapabilities("POST", "/channels/bot-remove", names)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code < 400 {
			t.Fatal("accepted missing CSRF/authentication evidence", rec.Code)
		}
	}
	if rec := request("POST", "/channels/bot-save", "name=example-bot&kind=discord&machine_id=machine-example&agent_type=hermes&token_ref=env%3A%2F%2FCHANNEL_WEB_SECRET&status=active&notes=Example", true, false); rec.Code != 303 {
		t.Fatal("bot save", rec.Code, rec.Body.String())
	}
	for _, path := range []string{"/channels", "/v1/operator/channels"} {
		rec := request("GET", path, "", false, false)
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "env://CHANNEL_WEB_SECRET") || !strings.Contains(rec.Body.String(), "example-bot") {
			t.Fatal("bot projection", rec.Code)
		}
	}
	if rec := request("POST", "/channels/bot-remove", "name=example-bot", true, false); rec.Code != 303 {
		t.Fatal("bot remove", rec.Code)
	}
	if rec := request("POST", "/channels/save", "id=second&kind=webhook&url_ref=env%3A%2F%2FCHANNEL_WEB_URL", true, false); rec.Code != 303 {
		t.Fatal("admin save", rec.Code)
	}
	if rec := request("POST", "/channels/remove", "id=second", true, false); rec.Code != 303 {
		t.Fatal("admin remove", rec.Code)
	}
	for _, path := range []string{"/channels", "/v1/operator/channels"} {
		rec := request("GET", path, "", false, false)
		if rec.Code != 200 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body.String())
		}
		if path == "/channels" && (!strings.Contains(rec.Body.String(), "</html>") || strings.Contains(rec.Body.String(), "Send test message")) {
			t.Fatal("operator page")
		}
	}
	for _, op := range []string{"test", "bind", "unbind", "remove", "save", "bot-save", "bot-remove"} {
		body := url.Values{"id": {"example"}, "machine_id": {"machine-example"}}.Encode()
		if rec := request("POST", "/channels/"+op, body, false, false); rec.Code != 403 {
			t.Fatalf("operator %s: %d", op, rec.Code)
		}
		if rec := request("POST", "/channels/"+op, body, true, true); rec.Code != 403 {
			t.Fatalf("CSRF %s: %d", op, rec.Code)
		}
	}
	for _, op := range []string{"test", "bind", "unbind"} {
		if rec := request("POST", "/channels/"+op, "id=example&machine_id=machine-example", true, false); rec.Code != 303 {
			t.Fatalf("admin %s: %d %s", op, rec.Code, rec.Body.String())
		}
		bindings, e := st.ChannelBindings()
		if e != nil {
			t.Fatal(e)
		}
		if op == "bind" && len(bindings) != 1 || op == "unbind" && len(bindings) != 0 {
			t.Fatal(bindings)
		}
	}
	if calls != 1 {
		t.Fatal("unauthorized delivery", calls)
	}
	entries, e := st.Audit("", 100)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, a := range entries {
		if a.Action == store.AuditChannelTest && a.OK {
			found = true
		}
	}
	if !found {
		t.Fatal("test not audited")
	}
	s.SetSecretProvider(secretFailureProvider{})
	for _, path := range []string{"/channels", "/v1/operator/channels"} {
		if r := request("GET", path, "", true, false); r.Code != 200 {
			t.Fatal(r.Code)
		}
	}
	if r := request("POST", "/channels/test", "id=example", true, false); r.Code != 502 {
		t.Fatal(r.Code)
	}
	s.SetSecretProvider(secrets.New(nil))
	if _, e := st.DB().Exec("CREATE TRIGGER channel_test_audit_failure BEFORE INSERT ON audit_log WHEN NEW.action='channel-test' BEGIN SELECT RAISE(ABORT,'unavailable'); END"); e != nil {
		t.Fatal(e)
	}
	if rec := request("POST", "/channels/test", "id=example", true, false); rec.Code != 502 {
		t.Fatal(rec.Code)
	}
	if calls != 1 {
		t.Fatal("delivery proceeded without audit")
	}
	if strings.Contains(logs.String(), canary) || strings.Contains(logs.String(), "sentinel-secret-web") {
		t.Fatal("secret logged")
	}
}

func TestDiscordChannelUIAndAPINeverExposeWebhook(t *testing.T) {
	s, st := newServer(t)
	const canary = "discord-webhook-path-canary"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, canary)
	}))
	defer target.Close()
	t.Setenv("DISCORD_WEB_TEST_URL", target.URL+"/webhooks/123/"+canary)
	s.SetSecretProvider(secrets.New(nil))
	if e := st.MutateChannel(context.Background(), "save", channels.Config{ID: "discord-example", Kind: "discord", URLRef: "env://DISCORD_WEB_TEST_URL"}, "", store.AuditEntry{}); e != nil {
		t.Fatal(e)
	}
	names, _ := operatorauth.NamesForPrefix("example.com/cap/clawctl")
	mux := http.NewServeMux()
	s.Routes(mux)
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	for _, path := range []string{"/channels", "/v1/operator/channels", "/channels/test"} {
		method := "GET"
		if path == "/channels/test" {
			method = "POST"
		}
		req := requestWithCapabilities(method, path, names)
		if method == "POST" {
			req.Header.Set("Sec-Fetch-Site", "same-origin")
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Body = io.NopCloser(strings.NewReader("id=discord-example"))
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		expected := 200
		if method == "POST" {
			expected = 502
		}
		if rec.Code != expected {
			t.Fatal(path, rec.Code)
		}
		for _, secret := range []string{canary, target.URL, "/webhooks/123/", "env://DISCORD_WEB_TEST_URL"} {
			if strings.Contains(rec.Body.String(), secret) || strings.Contains(logs.String(), secret) {
				t.Fatal("Discord secret exposed")
			}
		}
	}
	for _, path := range []string{"/channels", "/v1/operator/channels", "/channels/bot-save", "/channels/bot-remove"} {
		method := "GET"
		if strings.Contains(path, "bot-") {
			method = "POST"
		}
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		if rec.Code < 400 {
			t.Fatal("unauthenticated request accepted", path, rec.Code)
		}
	}
}

func TestInboundAdministrationAndOffDefault(t *testing.T) {
	s, st := newServer(t)
	account, err := st.CreateFirstAdmin("admin", "long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	s.Routes(mux)
	s.InboundRoutes(mux)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("POST", "/v1/channels/sample/inbound", strings.NewReader(`{}`)))
	if w.Code != 404 {
		t.Fatal("off default", w.Code)
	}
	body := url.Values{"id": {"sample"}, "user_id": {"123"}, "account_id": {account.AccountID}}.Encode()
	for _, admin := range []bool{false, true} {
		caps := operatorauth.CapabilityNames{View: "view"}
		if admin {
			caps.Admin = "admin"
		}
		r := requestWithCapabilities("POST", "/channels/allow-save", caps)
		r.Header.Set("Sec-Fetch-Site", "same-origin")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Body = io.NopCloser(strings.NewReader(body))
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if admin && w.Code != 303 || !admin && w.Code != 403 {
			t.Fatal(w.Code)
		}
	}
	for _, admin := range []bool{false, true} {
		caps := operatorauth.CapabilityNames{View: "view"}
		if admin {
			caps.Admin = "admin"
		}
		w = httptest.NewRecorder()
		mux.ServeHTTP(w, requestWithCapabilities("GET", "/v1/operator/channels", caps))
		if w.Code != 200 {
			t.Fatal(w.Code)
		}
		if strings.Contains(w.Body.String(), account.AccountID) != admin {
			t.Fatal("allowlist visibility")
		}
	}
}
