package chat

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/localauth"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/secrets"
	"github.com/teddashh/AI-Intune/internal/store"
)

func fixture(t *testing.T) (*Engine, Config, string) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	account, err := st.CreateFirstAdmin("admin", "a-long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, user := range []string{"1", "2"} {
		if err = st.MutateChatUser(context.Background(), store.ChatUser{ChannelID: "sample", UserID: user, AccountID: account.AccountID}, false, store.AuditEntry{}); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES('machine','Machine','2026-01-01T00:00:00Z')`, `INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,last_reading) VALUES('alert','machine','capacity','critical','2026-01-01T00:00:00Z','{}')`} {
		if _, err = st.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	c := Config{ID: "sample", Kind: "telegram", Enabled: true, Destination: "42", SelfID: "99", SecretRef: "env://CHAT_SECRET", TokenRef: "env://CHAT_TOKEN", ApprovalSeconds: 600}
	t.Setenv("CHAT_SECRET", "inbound-secret-canary")
	t.Setenv("CHAT_TOKEN", "bot-token-canary")
	return New([]Config{c}, st, operator.New(st), secrets.New(nil)), c, account.AccountID
}
func TestApprovalLifecycle(t *testing.T) {
	for _, mode := range []string{"approve", "deny", "expiry", "unknown", "insufficient", "revoke", "wrong-destination"} {
		t.Run(mode, func(t *testing.T) {
			e, c, account := fixture(t)
			ctx := context.Background()
			v := event{id: "request", user: "1", destination: "42", command: "ack-alert alert"}
			r := e.execute(ctx, c, v)
			if r.approval == "" {
				t.Fatalf("no approval: %+v", r)
			}
			v = event{id: "decision", user: "2", destination: "42", approval: r.approval, decision: "approve"}
			switch mode {
			case "deny":
				v.decision = "deny"
			case "expiry":
				e.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
			case "unknown":
				v.user = "3"
			case "insufficient":
				// The current schema only admits admins. Simulate a future restricted role
				// to ensure chat fails closed through the shared account capability function.
				if _, err := e.store.DB().Exec("PRAGMA ignore_check_constraints=ON"); err != nil {
					t.Fatal(err)
				}
				if _, err := e.store.DB().Exec("UPDATE hub_accounts SET role='viewer' WHERE account_id=?", account); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				_ = e.store.MutateChatUser(ctx, store.ChatUser{ChannelID: c.ID, UserID: "1"}, true, store.AuditEntry{})
			case "wrong-destination":
				v.destination = "other"
			}
			response := e.execute(ctx, c, v)
			var ack any
			if err := e.store.DB().QueryRow("SELECT acknowledged_at FROM disk_alerts WHERE id='alert'").Scan(&ack); err != nil {
				t.Fatal(err)
			}
			if mode == "approve" {
				if ack == nil || response.text != "alert acknowledged" {
					t.Fatal(response, ack)
				}
				v.id = "decision2"
				if rr := e.execute(ctx, c, v); rr.text != "approval unavailable or expired" {
					t.Fatal("reused approval", rr)
				}
			} else if ack != nil {
				t.Fatal("unexpected mutation")
			}
		})
	}
}
func TestPermissionParity(t *testing.T) {
	e, c, _ := fixture(t)
	p, ok := e.principal(c.ID, "1")
	if !ok {
		t.Fatal("mapping")
	}
	names := p.GrantedCapabilities
	account, err := e.store.VerifyPassword("admin", "a-long-test-password", "127.0.0.1")
	if err != nil {
		t.Fatal(err)
	}
	token, err := e.store.CreateSession(account, "127.0.0.1", "test")
	if err != nil {
		t.Fatal(err)
	}
	webAuth, err := localauth.New(e.store, false, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, permission := range []operatorauth.Permission{operatorauth.View, operatorauth.Operate, operatorauth.Admin} {
		r := httptest.NewRequest("GET", "/", nil)
		r.AddCookie(&http.Cookie{Name: localauth.CookieName(false), Value: token})
		_, decision := webAuth.Authorize(r, permission)
		if decision.Allowed != p.Has(permission) {
			t.Fatal("web/chat permission mismatch")
		}
	}
	for _, a := range []store.HubAccount{{AccountID: "sample", Role: "admin"}, {AccountID: "sample", Role: "viewer"}, {AccountID: "sample", Role: "admin", Disabled: true}} {
		shared := localauth.AccountPrincipal(a, names)
		for _, permission := range []operatorauth.Permission{operatorauth.View, operatorauth.Operate, operatorauth.Admin} {
			if shared.Has(permission) != (a.Role == "admin" && !a.Disabled) {
				t.Fatal("capability parity")
			}
		}
	}
}
func TestReplayLoopsAllowlistLimitsAndDenylist(t *testing.T) {
	e, c, _ := fixture(t)
	ctx := context.Background()
	v := event{id: "event", user: "1", destination: c.Destination, command: "status"}
	if e.execute(ctx, c, v).text == "" {
		t.Fatal("status")
	}
	if e.execute(ctx, c, v).text != "" {
		t.Fatal("replay")
	}
	for _, v := range []event{{id: "bot", user: "1", bot: true, destination: c.Destination, command: "status"}, {id: "self", user: c.SelfID, destination: c.Destination, command: "status"}, {id: "unknown", user: "unknown", destination: c.Destination, command: "status"}} {
		if e.execute(ctx, c, v).text != "" {
			t.Fatal("must ignore")
		}
	}
	for i, cmd := range []string{"delete-machine", "mfa", "auth-change", "token-create", "secret-set", "password", "terminal", "script-run"} {
		if !Dangerous(cmd) {
			t.Fatal(cmd)
		}
		v.id = fmt.Sprint(i)
		v.command = cmd
		rr := e.execute(ctx, c, v)
		if rr.approval != "" || rr.text != "action blocked" {
			t.Fatal("dangerous approval or execution", rr)
		}
	}
	v.id = "limited"
	if e.execute(ctx, c, v).text != "" {
		t.Fatal("user limit")
	}
	for i := 0; i < 60; i++ {
		if !e.rate("channel", 60, time.Now()) {
			t.Fatal("early limit")
		}
	}
	if e.rate("channel", 60, time.Now()) {
		t.Fatal("channel limit")
	}
}
func request(e *Engine, c Config, body, secret string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "/v1/channels/sample/inbound", strings.NewReader(body))
	r.SetPathValue("id", c.ID)
	r.Header.Set("X-Telegram-Bot-Api-Secret-Token", secret)
	w := httptest.NewRecorder()
	e.ServeHTTP(w, r)
	return w
}
func TestTelegramHTTPAndNoSecrets(t *testing.T) {
	e, c, _ := fixture(t)
	var logs bytes.Buffer
	old := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(old)
	defer func() {
		if strings.Contains(logs.String(), "canary") {
			t.Error("secret in logs")
		}
	}()
	body := fmt.Sprintf(`{"update_id":1,"message":{"from":{"id":1},"chat":{"id":42},"date":%d,"text":"/ack-alert alert"}}`, time.Now().Unix())
	w := request(e, c, body, "bad")
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
	w = request(e, c, body, "inbound-secret-canary")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "Approve") {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "canary") {
		t.Fatal("secret leak")
	}
	if w = request(e, c, body, "inbound-secret-canary"); w.Code != 204 {
		t.Fatal("replay", w.Code)
	}
	if w = request(e, c, strings.Replace(body, `"id":1`, `"id":3`, 1), "inbound-secret-canary"); w.Code != 204 {
		t.Fatal("unknown")
	}
	statuses, _ := json.Marshal(e.Status())
	if strings.Contains(string(statuses), "env://") {
		t.Fatal("reference leak")
	}
}
func TestDiscordHTTP(t *testing.T) {
	e, c, _ := fixture(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c.Kind = "discord"
	c.PublicKeyRef = "env://CHAT_PUBLIC"
	e.configs[c.ID] = c
	t.Setenv("CHAT_PUBLIC", hex.EncodeToString(pub))
	send := func(body string, tampered bool) *httptest.ResponseRecorder {
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		signature := hex.EncodeToString(ed25519.Sign(priv, []byte(ts+body)))
		if tampered {
			body += " "
		}
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		r.SetPathValue("id", c.ID)
		r.Header.Set("X-Signature-Ed25519", signature)
		r.Header.Set("X-Signature-Timestamp", ts)
		w := httptest.NewRecorder()
		e.ServeHTTP(w, r)
		return w
	}
	if w := send(`{"type":1}`, false); w.Code != 200 || !strings.Contains(w.Body.String(), `"type":1`) {
		t.Fatal(w.Body.String())
	}
	if w := send(`{"type":1}`, true); w.Code != 401 {
		t.Fatal("tamper")
	}
	body := `{"type":2,"id":"interaction","channel_id":"42","member":{"user":{"id":"1"}},"data":{"name":"ack-alert","options":[{"name":"alert_id","value":"alert"}]}}`
	w := send(body, false)
	if !strings.Contains(w.Body.String(), "custom_id") {
		t.Fatal(w.Body.String())
	}
	if w := send(body, false); w.Code != 204 {
		t.Fatal("interaction replay")
	}
	approvals, err := e.store.PendingChatApprovals(time.Now())
	if err != nil || len(approvals) != 1 {
		t.Fatal(approvals, err)
	}
	button := fmt.Sprintf(`{"type":3,"id":"button","channel_id":"42","user":{"id":"2"},"data":{"custom_id":"approve:%s"}}`, approvals[0].ID)
	if w := send(button, false); !strings.Contains(w.Body.String(), "alert acknowledged") {
		t.Fatal(w.Body.String())
	}
}

func TestConcurrentApprovalAndDurableReplay(t *testing.T) {
	e, c, _ := fixture(t)
	ctx := context.Background()
	r := e.execute(ctx, c, event{id: "request", user: "1", destination: "42", command: "ack-alert alert"})
	if r.approval == "" {
		t.Fatal(r)
	}
	results := make(chan reply, 2)
	for i := 0; i < 2; i++ {
		go func(i int) {
			results <- e.execute(ctx, c, event{id: fmt.Sprint("click", i), user: "2", destination: "42", approval: r.approval, decision: "approve"})
		}(i)
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if (<-results).text == "alert acknowledged" {
			successes++
		}
	}
	if successes != 1 {
		t.Fatal("one-time concurrency", successes)
	}
	replacement := New([]Config{c}, e.store, e.service, e.resolver)
	if replacement.execute(ctx, c, event{id: "request", user: "1", destination: "42", command: "ack-alert alert"}).text != "" {
		t.Fatal("restart replay")
	}
	var n int
	if err := e.store.DB().QueryRow("SELECT COUNT(*) FROM audit_log WHERE action='disk_alert_ack' AND outcome='ok'").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatal("duplicate action", n)
	}
}
func TestNoSecretInAuditAndFailClosed(t *testing.T) {
	e, c, _ := fixture(t)
	ctx := context.Background()
	for i, cmd := range []string{"status", "ack-alert alert", "secret-create"} {
		e.execute(ctx, c, event{id: fmt.Sprint(i), user: "1", destination: c.Destination, command: cmd})
	}
	rows, err := e.store.DB().Query("SELECT subject,COALESCE(detail,''),COALESCE(reason,'') FROM audit_log")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var a, b, c string
		if err = rows.Scan(&a, &b, &c); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(a+b+c, "canary") {
			t.Fatal("secret in audit")
		}
	}
	rows.Close()
	if _, err = e.store.DB().Exec("DROP TABLE audit_log"); err != nil {
		t.Fatal(err)
	}
	if r := e.execute(ctx, c, event{id: "fail", user: "1", destination: c.Destination, command: "ack-alert alert"}); r.text != "" || r.approval != "" {
		t.Fatal("audit failure did not close")
	}
}
func TestReplayCacheBound(t *testing.T) {
	e, c, _ := fixture(t)
	now := time.Now()
	if _, err := e.store.DB().Exec(`WITH RECURSIVE seq(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM seq WHERE x<10000) INSERT INTO chat_events SELECT 'sample',CAST(x AS TEXT),? FROM seq`, now.Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if fresh, err := e.store.ClaimChatEvent(context.Background(), c.ID, "overflow", now); err != nil || fresh {
		t.Fatal(fresh, err)
	}
	if fresh, err := e.store.ClaimChatEvent(context.Background(), c.ID, "new", now.Add(2*time.Hour)); err != nil || !fresh {
		t.Fatal(fresh, err)
	}
}

func TestReadCommands(t *testing.T) {
	e, c, _ := fixture(t)
	for i, cmd := range []string{"status", "machines", "jobs", "alerts"} {
		r := e.execute(context.Background(), c, event{id: fmt.Sprint(i), user: "1", destination: c.Destination, command: cmd})
		if r.text == "" || r.text == "query failed" || r.approval != "" {
			t.Fatal(cmd, r)
		}
	}
}
func TestConfigOptIn(t *testing.T) {
	if cs, err := Load(""); err != nil || len(cs) != 0 {
		t.Fatal(cs, err)
	}
	path := filepath.Join(t.TempDir(), "inbound.json")
	raw := `[{"id":"sample","kind":"telegram","destination":"42","self_id":"99","token_ref":"env://BOT_TOKEN","secret_ref":"env://WEBHOOK_SECRET"}]`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	cs, err := Load(path)
	if err != nil || len(cs) != 1 || cs[0].Enabled || cs[0].ApprovalSeconds != 600 {
		t.Fatal(cs, err)
	}
	for _, invalid := range []string{raw + ` {}`, strings.Replace(raw, "env://WEBHOOK_SECRET", "raw-canary", 1), strings.Replace(raw, `"sample"`, `"invalid/path"`, 1)} {
		if err = os.WriteFile(path, []byte(invalid), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = Load(path); err == nil || strings.Contains(err.Error(), "canary") {
			t.Fatal("invalid config or leaked error", err)
		}
	}
}
