package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func joinHTTPRequest(mux *http.ServeMux, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:1234"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}
func TestJoinPublicFlowAndHumanApproval(t *testing.T) {
	s, _, bundles := configuredAgentBundleServer(t)
	s.SetHubBase("https://hub.example.com")
	mux := http.NewServeMux()
	s.JoinPublicRoutes(mux)
	script := joinHTTPRequest(mux, "GET", "/join.sh", "")
	if script.Code != 200 || script.Header().Get("Content-Type") != "text/x-shellscript" || strings.Contains(script.Body.String(), "@@CLAWCTL_PUBLIC_URL@@") || !strings.Contains(script.Body.String(), "hub='https://hub.example.com'") {
		t.Fatal("invalid public script")
	}
	response := joinHTTPRequest(mux, "POST", "/v1/join/start", `{"hostname":"host-b","os":"linux","arch":"amd64","user":"operator"}`)
	var started operator.JoinStarted
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &started) != nil {
		t.Fatalf("start: %d", response.Code)
	}
	pending := joinHTTPRequest(mux, "POST", "/v1/join/poll", `{"device_secret":"`+started.Secret+`"}`)
	if pending.Code != 202 || pending.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("pending contract")
	}
	req := httptest.NewRequest("GET", "/v1/join/bundle/amd64", nil)
	req.Header.Set("Authorization", "Bearer "+started.Secret)
	download := httptest.NewRecorder()
	mux.ServeHTTP(download, req)
	if download.Code != 200 || download.Body.String() != string(bundles["amd64"]) {
		t.Fatal("join bundle download")
	}
	viewer := diskWebPrincipal(false, false, "")
	admin := diskWebPrincipal(true, false, "")
	view := diskWebRequest(t, s, "GET", "/machines/join", nil, viewer, false)
	if view.Code != 200 || !strings.Contains(view.Body.String(), started.Code) || strings.Contains(view.Body.String(), "<button name=\"decision\"") {
		t.Fatal("viewer join page")
	}
	for _, term := range []string{"Tailscale keys are not configured", "Host-B", "192.0.2.10"} {
		if !strings.Contains(view.Body.String(), term) {
			t.Errorf("missing UI copy %s", term)
		}
	}
	form := url.Values{"join_id": {started.Code}, "display_name": {"Host-B"}, "decision": {"approve"}}
	denied := diskWebRequest(t, s, "POST", "/machines/join/decide", form, viewer, false)
	if denied.Code != 403 {
		t.Fatal("viewer approved")
	}
	approved := diskWebRequest(t, s, "POST", "/machines/join/decide", form, admin, false)
	if approved.Code != 303 {
		t.Fatalf("approval status %d", approved.Code)
	}
	poll := joinHTTPRequest(mux, "POST", "/v1/join/poll", `{"device_secret":"`+started.Secret+`"}`)
	var payload operator.JoinPayload
	if poll.Code != 200 || json.Unmarshal(poll.Body.Bytes(), &payload) != nil || payload.EnrollToken == "" || payload.Bundle.SHA256 == "" || payload.Tailscale != nil {
		t.Fatal("approval payload")
	}
	replay := joinHTTPRequest(mux, "POST", "/v1/join/poll", `{"device_secret":"`+started.Secret+`"}`)
	if replay.Code != 410 || strings.Contains(replay.Body.String(), payload.EnrollToken) {
		t.Fatal("approval replay")
	}
	download = httptest.NewRecorder()
	mux.ServeHTTP(download, req)
	if download.Code != 404 {
		t.Fatal("redeemed download authorization")
	}
	list := diskWebRequest(t, s, "GET", "/v1/operator/joins", nil, viewer, false)
	if list.Code != 200 || strings.Contains(list.Body.String(), payload.EnrollToken) || strings.Contains(list.Body.String(), started.Secret) {
		t.Fatal("operator read leaked secret")
	}
}
func TestJoinStrictJSONAndPublicURL(t *testing.T) {
	s, _, _ := configuredAgentBundleServer(t)
	s.SetHubBase("https://hub.example.com")
	mux := http.NewServeMux()
	s.JoinPublicRoutes(mux)
	for _, body := range []string{`{`, `null`, `[]`, `{} {}`, `{"hostname":"a","hostname":"b"}`, `{"extra":"field"}`, `{"hostname":null}`, `{"device_secret":true}`, strings.Repeat(" ", 2049)} {
		w := joinHTTPRequest(mux, "POST", "/v1/join/start", body)
		if w.Code != 400 || w.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("invalid JSON status %d", w.Code)
		}
	}
	for _, base := range []string{"http://hub.example.com", "https://hub.example.com/path", "https://user@hub.example.com", "https://hub.example.com;id", "https://hub.example.com?x=y", "https://hub.example.com/#x"} {
		s.SetHubBase(base)
		w := joinHTTPRequest(mux, "GET", "/join.sh", "")
		if w.Code != 503 {
			t.Errorf("unsafe URL accepted %q", base)
		}
	}
	s.SetHubBase("https://hub.example.com")
	html := renderWithCapabilities(t, s, "/machines/join", operatorauth.CapabilityNames{View: "view"})
	if !strings.Contains(html, "No machines are waiting.") || !strings.Contains(html, "curl -fsSL https://hub.example.com/join.sh | sudo bash") {
		t.Fatal("empty state")
	}
}

func TestJoinOSAndArchChooseApprovedBundle(t *testing.T) {
	for _, osName := range []string{"linux", "windows"} {
		for _, arch := range []string{"amd64", "arm64"} {
			t.Run(osName+"-"+arch, func(t *testing.T) {
				s, _, bundles := configuredWindowsAgentBundleServer(t)
				s.SetHubBase("https://hub.example.com")
				mux := http.NewServeMux()
				s.JoinPublicRoutes(mux)
				res := joinHTTPRequest(mux, "POST", "/v1/join/start", `{"hostname":"host","os":"`+osName+`","arch":"`+arch+`","user":"operator"}`)
				var started operator.JoinStarted
				if res.Code != 200 || json.Unmarshal(res.Body.Bytes(), &started) != nil {
					t.Fatal("start failed")
				}
				key := osName + "-" + arch
				contentsKey := key
				if osName == "linux" {
					contentsKey = arch
				}
				for _, downloadKey := range []string{"amd64", "arm64", "linux-amd64", "linux-arm64", "windows-amd64", "windows-arm64"} {
					req := httptest.NewRequest("GET", "/v1/join/bundle/"+downloadKey, nil)
					req.Header.Set("Authorization", "Bearer "+started.Secret)
					w := httptest.NewRecorder()
					mux.ServeHTTP(w, req)
					allowed := downloadKey == key || osName == "linux" && downloadKey == arch
					if allowed && (w.Code != 200 || w.Body.String() != string(bundles[contentsKey])) {
						t.Fatal("wrong bundle delivered")
					}
					if !allowed && w.Code != 404 {
						t.Errorf("cross-platform download allowed: %s", downloadKey)
					}
				}
				page := diskWebRequest(t, s, "GET", "/machines/join", nil, diskWebPrincipal(true, false, ""), false)
				if !strings.Contains(page.Body.String(), osName+" / "+arch) {
					t.Fatal("approval page lacks OS and arch")
				}
				form := url.Values{"join_id": {started.Code}, "display_name": {"Host"}, "decision": {"approve"}}
				if w := diskWebRequest(t, s, "POST", "/machines/join/decide", form, diskWebPrincipal(true, false, ""), false); w.Code != 303 {
					t.Fatal("approval failed")
				}
				poll := joinHTTPRequest(mux, "POST", "/v1/join/poll", `{"device_secret":"`+started.Secret+`"}`)
				var payload operator.JoinPayload
				if poll.Code != 200 || json.Unmarshal(poll.Body.Bytes(), &payload) != nil {
					t.Fatal("poll failed")
				}
				if payload.Bundle.URL != "https://hub.example.com/v1/join/bundle/"+key || payload.Bundle.SHA256 != s.agentBundles.items[key].SHA256 {
					t.Fatal("approval selected wrong platform digest")
				}
			})
		}
	}
}

func TestPublicPowerShellBootstrap(t *testing.T) {
	s, _, _ := configuredAgentBundleServer(t)
	s.SetHubBase("https://hub.example.com")
	mux := http.NewServeMux()
	s.JoinPublicRoutes(mux)
	res := joinHTTPRequest(mux, "GET", "/join.ps1", "")
	script := res.Body.String()
	if res.Code != 200 || res.Header().Get("Cache-Control") != "no-store" || strings.Contains(script, "@@CLAWCTL_PUBLIC_URL@@") || !strings.Contains(script, "$Hub = 'https://hub.example.com'") {
		t.Fatal("public script not templated")
	}
	for _, term := range []string{
		"[switch]$JobsEnabled", "$jobs = 'false'", "--token-file $TokenFile", "--jobs-enabled $Jobs",
		"Join code:", "/machines/join", "expires_at", "Get-FileHash", "SHA256", "Expand-JoinBundle",
		"Unsafe agent archive member.", "Remove-Item -LiteralPath $work", "WindowsBuiltInRole]::Administrator",
		"function Protect-JoinInstallerOutput", "$Text.Replace($secret,", `(?:token|secret)`, `\bbearer`,
		"Invoke-JoinInstaller (Join-Path $stage 'install-agent-windows.ps1')",
		"@($approved.enroll_token, $started.device_secret)", "*>&1", "$LASTEXITCODE -ne 0",
		"$line = Protect-JoinInstallerOutput ([string]$_) $Secrets",
		"Add-Content -LiteralPath $LogFile -Value $line", "Last redacted output lines:",
	} {
		if !strings.Contains(script, term) {
			t.Errorf("bootstrap missing %q", term)
		}
	}
	if strings.Contains(script, "operator_token") || strings.Contains(script, "Write-Host $started") || strings.Contains(script, "Write-Host $approved") {
		t.Fatal("bootstrap exposes credentials")
	}
	if strings.Contains(script, "*> $null") {
		t.Fatal("bootstrap discards installer diagnostics")
	}
	s.SetHubBase("http://hub.example.com")
	if w := joinHTTPRequest(mux, "GET", "/join.ps1", ""); w.Code != 503 {
		t.Fatal("script served without HTTPS hub")
	}
}

func TestJoinRejectsUnknownOSAndMissingWindowsRelease(t *testing.T) {
	s, _, _ := configuredAgentBundleServer(t)
	s.SetHubBase("https://hub.example.com")
	mux := http.NewServeMux()
	s.JoinPublicRoutes(mux)
	if w := joinHTTPRequest(mux, "POST", "/v1/join/start", `{"hostname":"host","os":"plan9","arch":"amd64","user":"operator"}`); w.Code != 400 {
		t.Fatal("unknown OS accepted")
	}
	w := joinHTTPRequest(mux, "POST", "/v1/join/start", `{"hostname":"host","os":"windows","arch":"amd64","user":"Administrator"}`)
	var started operator.JoinStarted
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &started) != nil {
		t.Fatal("Administrator join rejected")
	}
	form := url.Values{"join_id": {started.Code}, "display_name": {"Host"}, "decision": {"approve"}}
	if approved := diskWebRequest(t, s, "POST", "/machines/join/decide", form, diskWebPrincipal(true, false, ""), false); approved.Code != 409 {
		t.Fatal("missing Windows release fell back to Linux")
	}
}
