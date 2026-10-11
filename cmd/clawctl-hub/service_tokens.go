package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"
	"net/netip"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/clientip"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

var serviceTokenPatterns = []string{"GET /v1/operator/service-tokens/self", "POST /v1/operator/service-tokens/rotate", "GET /account/service-tokens", "POST /account/service-tokens/create", "POST /account/service-tokens/revoke"}

type serviceFormRoute struct {
	Pattern, Label, Description string
	Selected                    bool
}
type serviceFormData struct {
	Tokens                                    []store.ServiceToken
	Message, Secret, CreatedID, CreatedExpiry string
	Name, Scope, Expiry, CIDRs, MaxLifetime   string
	Routes                                    []serviceFormRoute
}

// Only the one-time creation response permits this exact script through a CSP hash.
const serviceTokenCopyScript = `const t=document.getElementById("issued-token");const b=document.getElementById("copy-token");if(t&&b){t.addEventListener("focus",()=>t.select());b.addEventListener("click",()=>{t.select();if(navigator.clipboard){navigator.clipboard.writeText(t.value).then(()=>{b.textContent="Copied";},()=>{b.textContent="Selected; copy manually";});}else{b.textContent="Selected; copy manually";}});}`

var serviceTokenForm = template.Must(template.New("service-tokens").Parse(`<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Service tokens</title><style>body{font:16px system-ui;max-width:1100px;margin:2rem auto;padding:1rem}label{display:block;margin:.6rem 0}input,select,textarea,button{font:inherit}table{border-collapse:collapse}th,td{padding:.5rem;border:1px solid #ccc;text-align:left}small{display:block}fieldset{margin:1rem 0}</style></head><body><a href="/account/security">Account security</a><h1>Service tokens</h1><p role="alert">{{.Message}}</p>
{{if .Secret}}<label for="issued-token">New service token</label><input id="issued-token" readonly size="72" value="{{.Secret}}"><button id="copy-token" type="button">Copy token</button><script>` + serviceTokenCopyScript + `</script><p>Save it now; it will not be shown again.</p><p>Token ID: {{.CreatedID}} · Expires: {{.CreatedExpiry}}</p>{{end}}
<h2>Create token</h2><form method="post" action="/account/service-tokens/create">
<label for="name">Name</label><input id="name" name="name" value="{{.Name}}" required maxlength="64" pattern="[a-zA-Z0-9_-]{1,64}" aria-describedby="name-help"><small id="name-help">Letters, digits, - and _ only; 1–64 characters.</small>
<label for="scope">Scope</label><select id="scope" name="scope"><option value="view" {{if eq .Scope "view"}}selected{{end}}>view</option><option value="operate" {{if eq .Scope "operate"}}selected{{end}}>operate</option></select><small>view: read-only routes. operate: view plus running READ-only catalog scripts.</small>
<label for="expiry">Expiry</label><select id="expiry" name="expiry_days"><option value="30" {{if eq .Expiry "30"}}selected{{end}}>30 days</option><option value="60" {{if eq .Expiry "60"}}selected{{end}}>60 days</option><option value="90" {{if eq .Expiry "90"}}selected{{end}}>90 days</option></select>
<label for="max-lifetime">Maximum chain lifetime</label><select id="max-lifetime" name="max_lifetime"><option value="none">None (unlimited rotation)</option><option value="180" {{if eq .MaxLifetime "180"}}selected{{end}}>180 days</option><option value="365" {{if eq .MaxLifetime "365"}}selected{{end}}>365 days</option></select>
<fieldset><legend>Allowed routes</legend><small>Select exact API routes. Script-runs requires operate scope and accepts only READ catalog scripts.</small>{{range .Routes}}<label><input type="checkbox" name="routes" value="{{.Pattern}}" {{if .Selected}}checked{{end}}> {{.Label}} — {{.Description}} <code>{{.Pattern}}</code></label>{{end}}</fieldset>
<label for="cidrs">Optional source CIDRs</label><textarea id="cidrs" name="source_cidrs">{{.CIDRs}}</textarea><small>One network per line or comma-separated, e.g. 192.0.2.0/24. Empty allows any source IP.</small>
<label for="password">Current password</label><input id="password" type="password" name="password" required autocomplete="current-password">
<label for="code">Authenticator code</label><input id="code" name="code" required inputmode="numeric" autocomplete="one-time-code">
<button>Create selected routes</button><button name="preset" value="hermes-default">Create with Hermes default</button><small>Hermes default: supervision summaries, job list/details/evidence and script-runs preview/apply. Select operate scope.</small></form>
<h2>Existing tokens</h2><table><tr><th>ID / name</th><th>Scope</th><th>Status</th><th>Allowed routes / CIDRs</th><th>Expires</th><th>Revoke chain</th></tr>{{range .Tokens}}<tr><td>{{.ID}}<br>{{.Name}}</td><td>{{.Scope}}</td><td>{{.Status}}</td><td>{{range .Allowlist}}{{.}}<br>{{end}}{{range .SourceCIDRs}}{{.}}<br>{{end}}</td><td>{{.ExpiresAt}}</td><td><form method="post" action="/account/service-tokens/revoke"><input type="hidden" name="id" value="{{.ID}}"><label>Password <input type="password" name="password" required autocomplete="current-password"></label><label>Authenticator code <input name="code" required inputmode="numeric" autocomplete="one-time-code"></label><button>Revoke entire chain</button></form></td></tr>{{end}}</table></body></html>`))

var hermesServiceRoutes = []string{"GET /v1/operator/jobs-summary", "GET /v1/operator/approvals-summary", "GET /v1/operator/hub-status", "GET /v1/operator/jobs", "GET /v1/operator/jobs/{id}", "GET /v1/operator/jobs/{id}/evidence", "POST /v1/operator/script-runs/preview", "POST /v1/operator/script-runs"}

func validateServiceTokenForm(r *http.Request) (store.ServiceToken, string) {
	t := store.ServiceToken{Name: r.PostForm.Get("name"), Scope: r.PostForm.Get("scope"), SourceCIDRs: splitServiceList(r.PostForm.Get("source_cidrs"))}
	if !serviceTokenAuditName.MatchString(t.Name) {
		return t, "Name invalid: use 1–64 letters, digits, - or _."
	}
	if t.Scope != "view" && t.Scope != "operate" {
		return t, "Scope invalid: select view or operate."
	}
	days := 0
	switch r.PostForm.Get("expiry_days") {
	case "30":
		days = 30
	case "60":
		days = 60
	case "90":
		days = 90
	default:
		return t, "Expiry preset invalid: select 30, 60 or 90 days."
	}
	t.ExpiresAt = time.Now().UTC().Add(time.Duration(days) * 24 * time.Hour)
	switch r.PostForm.Get("max_lifetime") {
	case "", "none":
	case "180":
		t.MaxLifetimeSeconds = 180 * 86400
	case "365":
		t.MaxLifetimeSeconds = 365 * 86400
	default:
		return t, "Maximum lifetime invalid."
	}
	t.Allowlist = r.PostForm["routes"]
	if r.PostForm.Get("preset") == "hermes-default" {
		t.Allowlist = append([]string(nil), hermesServiceRoutes...)
	}
	if len(t.Allowlist) == 0 {
		return t, "No routes selected."
	}
	for _, route := range t.Allowlist {
		policy, ok := operatorRoutePolicies[route]
		if !ok || !policy.ServiceTokenEligible.eligible() || policy.ServiceTokenEligible == serviceEligibleSelf {
			if len(route) <= 256 && regexp.MustCompile(`^[A-Z]+ /[a-zA-Z0-9_{}./-]+$`).MatchString(route) {
				return t, "Route " + route + " is not eligible."
			}
			return t, "Selected route is not eligible."
		}
		if policy.ServiceTokenEligible == serviceEligibleReadScriptsOnly && t.Scope != "operate" {
			return t, "Script-runs requires operate scope."
		}
	}
	for _, cidr := range t.SourceCIDRs {
		if _, err := netip.ParsePrefix(cidr); err != nil {
			if len(cidr) <= 64 && regexp.MustCompile(`^[0-9a-fA-F:./]+$`).MatchString(cidr) {
				return t, "CIDR " + cidr + " invalid: enter a network prefix."
			}
			return t, "Source CIDR invalid: enter a network prefix."
		}
	}
	if len(t.SourceCIDRs) > 32 {
		return t, "Source CIDRs invalid: maximum 32 networks."
	}
	return t, ""
}

func registerServiceTokenRoutes(mux *http.ServeMux, st *store.Store, resolver clientip.Resolver) []string {
	limiter := newIPLimiter(10, 5)
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		p, ok := operatorauth.PrincipalFromContext(r.Context())
		metadata, formErr := serviceTokenManagementMetadata(w, r, p, resolver)
		source := metadata.SourceAddr
		if r.Method == http.MethodPost {
			response := &serviceResponseWriter{ResponseWriter: w}
			w = response
			defer func() {
				if response.status >= 400 {
					metadata.OK = false
					metadata.Detail = fmt.Sprintf("HTTP status %d", response.status)
					if err := st.RecordAudit(metadata); err != nil {
						log.Printf("service-token management denial audit unavailable: %v", err)
					}
				}
			}()
		}
		if !ok || p.AuthMethod != operatorauth.AuthMethodLocalAccountSession || !p.Has(operatorauth.Admin) {
			http.NotFound(w, r)
			return
		}
		actor := strings.TrimPrefix(p.StableSubject(), "local-user:")
		enabled, err := st.MFAEnabled(actor)
		if err != nil || !enabled {
			http.Error(w, "MFA required", 403)
			return
		}
		message, secret := "", ""
		factorsVerified := false
		data := serviceFormData{Scope: "view", Expiry: "90"}
		if r.Method == "POST" {
			data.Name = r.PostForm.Get("name")
			data.Scope = r.PostForm.Get("scope")
			data.Expiry = r.PostForm.Get("expiry_days")
			data.CIDRs = r.PostForm.Get("source_cidrs")
			data.MaxLifetime = r.PostForm.Get("max_lifetime")
		}
		if r.Method == "POST" {
			status := 400
			err = formErr
			if !limiter.allow(source) {
				message = "Rate limited: too many attempts. Try again later."
				status = 429
				err = store.ErrServiceToken
			}
			if err == nil {
				var a store.HubAccount
				a, err = st.VerifyPassword(p.TailnetUserLogin, r.PostForm.Get("password"), source, metadata)
				if err == nil && a.AccountID != actor {
					err = store.ErrAccountAuth
				}
			}
			if err == nil {
				err = st.VerifyAdminTOTP(actor, source, r.PostForm.Get("code"), metadata)
				factorsVerified = err == nil
			}
			if err == nil {
				if strings.HasSuffix(r.URL.Path, "/create") {
					var token store.ServiceToken
					token, message = validateServiceTokenForm(r)
					if message != "" {
						err = store.ErrServiceToken
					} else {
						var created store.ServiceToken
						created, secret, err = st.CreateServiceToken(token, actor)
						data.CreatedID = created.ID
						data.CreatedExpiry = created.ExpiresAt.UTC().Format(time.RFC3339)
					}

				} else {
					err = st.RevokeServiceToken(r.PostForm.Get("id"), actor)
				}
			}
			if err != nil {
				if message == "" {
					if factorsVerified {
						message = "Service token could not be updated. Try again."
					} else {
						message = "Password or code incorrect."
					}
				}
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(status)
			}
		}
		tokens, err := st.ListServiceTokens()
		if err != nil {
			if secret == "" {
				http.Error(w, "Unavailable", 503)
				return
			}
			tokens = nil
			message = "Token created; the token list is temporarily unavailable."
		}
		if len(tokens) > 200 {
			tokens = tokens[:200]
			message += " Showing the latest 200 tokens; older entries are omitted."
		}
		_ = st.RecordAudit(store.AuditEntry{Action: "service-token-list", AuthSubject: p.StableSubject(), AuthMethod: p.AuthMethod, OK: true})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if secret != "" {
			hash := sha256.Sum256([]byte(serviceTokenCopyScript))
			w.Header().Set("Content-Security-Policy", lockedOperatorContentSecurityPolicy+"; script-src 'sha256-"+base64.StdEncoding.EncodeToString(hash[:])+"'")
		}
		data.Tokens = tokens
		data.Message = message
		data.Secret = secret
		for route, policy := range operatorRoutePolicies {
			if !policy.ServiceTokenEligible.eligible() || policy.ServiceTokenEligible == serviceEligibleSelf {
				continue
			}
			selected := false
			selectedRoutes := r.PostForm["routes"]
			if r.PostForm.Get("preset") == "hermes-default" {
				selectedRoutes = hermesServiceRoutes
			}
			for _, v := range selectedRoutes {
				if v == route {
					selected = true
				}
			}
			path := strings.TrimPrefix(strings.SplitN(route, " ", 2)[1], "/v1/operator/")
			label := strings.ReplaceAll(path, "-", " ")
			description := "Read " + label
			if policy.ServiceTokenEligible == serviceEligibleReadScriptsOnly {
				description = "Run READ-only catalog scripts (operate required)"
			}
			data.Routes = append(data.Routes, serviceFormRoute{route, label, description, selected})
		}
		sort.Slice(data.Routes, func(i, j int) bool { return data.Routes[i].Pattern < data.Routes[j].Pattern })
		_ = serviceTokenForm.Execute(w, data)
	}
	for _, pattern := range serviceTokenPatterns {
		if strings.Contains(pattern, "/v1/operator/") {
			mux.Handle(pattern, http.NotFoundHandler())
		} else {
			mux.HandleFunc(pattern, handler)
		}
	}
	return serviceTokenPatterns
}

// Resolve request metadata before admission or factor verification. Only exact
// management paths and validated target identifiers may enter the audit ledger.
func serviceTokenManagementMetadata(w http.ResponseWriter, r *http.Request, p operatorauth.Principal, resolver clientip.Resolver) (store.AuditEntry, error) {
	entry := store.AuditEntry{AuthSubject: p.StableSubject(), AuthMethod: p.AuthMethod, SourceAddr: resolver.Resolve(r), UserAgent: r.UserAgent()}
	field := ""
	switch r.URL.Path {
	case "/account/service-tokens/create":
		entry.Action, field = "service-token-create-denied", "name"
	case "/account/service-tokens/revoke":
		entry.Action, field = "service-token-revoke-denied", "id"
	}
	if r.Method != http.MethodPost || field == "" {
		return entry, nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	err := r.ParseForm()
	entry.Subject = "unavailable"
	if err == nil {
		entry.Subject = serviceTokenAuditTarget(field, r.PostForm[field])
	}
	return entry, err
}

// Do not persist credentials pasted into malformed target fields or ambiguous
// duplicate fields. Valid targets are bounded service names or UUID token IDs.
var serviceTokenAuditName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,64}$`)
var serviceTokenAuditID = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)

func serviceTokenAuditTarget(field string, values []string) string {
	if len(values) != 1 {
		return "unavailable"
	}
	if field == "name" && serviceTokenAuditName.MatchString(values[0]) {
		return values[0]
	}
	if field == "id" && serviceTokenAuditID.MatchString(values[0]) {
		return values[0]
	}
	return "unavailable"
}

func splitServiceList(v string) []string {
	var out []string
	for _, s := range strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

// serviceResponseWriter records the first final status, including implicit 200s.
type serviceResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *serviceResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *serviceResponseWriter) WriteHeader(status int) {
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
func (w *serviceResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(data)
}

func (b *operatorBoundary) serveServiceToken(w http.ResponseWriter, r *http.Request, pattern string, policy operatorRoutePolicy) {
	source := b.clientIP.Resolve(r)
	response := &serviceResponseWriter{ResponseWriter: w}
	principal := operatorauth.Principal{AuthMethod: operatorauth.AuthMethodServiceToken, SourceAddr: source}
	defer func() {
		panicked := recover()
		if panicked != nil {
			defer func() { panic(panicked) }()
		}
		status := response.status
		if panicked != nil && status == 0 {
			status = http.StatusInternalServerError
		}
		if status == 0 {
			status = http.StatusOK
		}
		entry := store.AuditEntry{Action: "service-token-request", AuthSubject: principal.StableSubject(), AuthMethod: principal.AuthMethod, Subject: pattern, SourceAddr: source, OK: status < 400, Detail: fmt.Sprintf("HTTP status %d", status)}
		var err error
		if status >= 400 {
			entry.Action = store.AuditOperatorDenied
			// Bound denial write I/O as well as ledger size, including 429 floods.
			admission := b.denials.admit(true, source)
			if admission.suppressedUnsafe != 0 {
				b.persistSuppressedDenials(admission)
			}
			if !admission.persistUnsafe {
				return
			}
			err = b.store.RecordOperatorDenial(entry)
		} else {
			err = b.store.RecordAudit(entry)
		}
		if err != nil {
			log.Printf("service-token request audit unavailable: %v", err)
		}
	}()
	if !b.serviceAttempts.allowWithCost(source, false) {
		writeOperatorBoundaryError(response, operatorJSON, 429, "RATE_LIMITED", "Too many attempts")
		return
	}
	secret := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	required := policy.Permission.String()
	if !policy.ServiceTokenEligible.eligible() {
		required = ""
	}
	token, err := b.store.AuthenticateServiceToken(secret, pattern, source, required)
	if token.Name != "" {
		principal.TailnetUserID = token.Name
		principal.TailnetUserLogin = "service:" + token.Name
		principal.NodeStableID = token.ID
	}
	if err != nil || !policy.ServiceTokenEligible.eligible() || policy.Permission == operatorauth.Admin {
		b.serviceAttempts.allow(source)
		writeOperatorBoundaryError(response, operatorJSON, 401, "UNAUTHENTICATED", "Authentication required")
		return
	}
	principal.GrantedCapabilities.View = "view"
	if token.Scope == "operate" {
		principal.GrantedCapabilities.Operate = "operate"
	}
	principal.AuthorizedCapability = policy.Permission.String()
	if policy.ServiceTokenEligible == serviceEligibleSelf {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Content-Type", "application/json")
		if r.Method == "GET" {
			_ = json.NewEncoder(response).Encode(map[string]any{"id": token.ID, "name": token.Name, "scope": token.Scope, "expires_at": token.ExpiresAt, "max_expiry": token.MaxExpiry()})
			return
		}
		r.Body = http.MaxBytesReader(response, r.Body, 1024)
		var body map[string]json.RawMessage
		decoder := json.NewDecoder(r.Body)
		if r.Header.Get("Content-Type") != "application/json" || decoder.Decode(&body) != nil || body == nil || len(body) != 0 {
			writeOperatorBoundaryError(response, operatorJSON, 400, "BAD_REQUEST", "Expected an empty JSON object")
			return
		}
		var trailing any
		if decoder.Decode(&trailing) != io.EOF {
			writeOperatorBoundaryError(response, operatorJSON, 400, "BAD_REQUEST", "Expected one JSON object")
			return
		}
		next, plaintext, e := b.store.RotateServiceToken(token.ID, source)
		if e != nil {
			status, code := 503, "UNAVAILABLE"
			switch {
			case errors.Is(e, store.ErrServiceTokenRotated):
				status, code = 409, "ALREADY_ROTATED"
			case errors.Is(e, store.ErrServiceTokenMaxLifetime):
				status, code = 403, "MAX_LIFETIME"
			case errors.Is(e, store.ErrServiceTokenRateLimit):
				status, code = 429, "RATE_LIMITED"
			case errors.Is(e, store.ErrServiceToken):
				status, code = 401, "UNAUTHENTICATED"
			}
			writeOperatorBoundaryError(response, operatorJSON, status, code, "Unable to rotate service token")
			return
		}
		_ = json.NewEncoder(response).Encode(map[string]any{"id": next.ID, "token": plaintext, "expires_at": next.ExpiresAt, "max_expiry": next.MaxExpiry()})
		return
	}
	b.csrfNext.ServeHTTP(response, operatorauth.WithPrincipal(r, principal))
}
