package main

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/localauth"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

var actionMFAForm = template.Must(template.New("step-up").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Confirm your identity</title><h1>Confirm your identity</h1><p>{{.Why}}</p><p role="alert">{{.Error}}</p><form method="post" action="{{.Action}}">{{range $key,$values := .Fields}}{{range $values}}<input type="hidden" name="{{$key}}" value="{{.}}">{{end}}{{end}}<label>Current password <input type="password" name="password" required maxlength="256" autocomplete="current-password"></label><label>Authenticator code <input name="code" required maxlength="6" autocomplete="one-time-code"></label><button>Confirm and continue</button></form></html>`))

// Account/security handlers retain their own factor checks because those flows
// may change the factor itself or require the current password independently.
func nativeAccountReauthentication(pattern string) bool {
	return operatorauth.DangerousAction(pattern) != "" && strings.Contains(pattern, " /account/")
}

func actionMFAWindow(pattern string, permission operatorauth.Permission, routine time.Duration) (time.Duration, string) {
	if why := operatorauth.DangerousAction(pattern); why != "" {
		return operatorauth.DangerousMFAWindow, "Fresh MFA is needed for " + why + "."
	}
	if routine <= 0 {
		routine = operatorauth.DefaultAdminMFAWindow
	}
	if permission == operatorauth.Admin || strings.Contains(pattern, "/schedules/") {
		return routine, "Your admin MFA window has expired. Confirm your identity to continue this action."
	}
	return 0, ""
}

func (b *operatorBoundary) authorizeActionMFA(w http.ResponseWriter, r *http.Request, pattern string, policy operatorRoutePolicy) bool {
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || p.AuthMethod != operatorauth.AuthMethodLocalAccountSession || b.cloud == nil || !b.cloud.requireMFA || r.Method == "GET" || r.Method == "HEAD" || isSecurityEnrollmentRoute(pattern) || nativeAccountReauthentication(pattern) {
		return true
	}
	window, why := actionMFAWindow(pattern, policy.Permission, b.cloud.adminMFAWindow)
	if window == 0 {
		return true
	}
	if operatorauth.MFAWithin(p.MFAVerifiedAt, time.Now(), window) {
		p.ActionMFAAuthorized = true
		*r = *operatorauth.WithPrincipal(r, p)
		return true
	}
	if policy.Representation != operatorHTML {
		writeOperatorBoundaryError(w, policy.Representation, 403, "MFA_STEP_UP_REQUIRED", why+" Use the Hub UI.")
		return false
	}
	if err := http.NewCrossOriginProtection().Check(r); err != nil {
		http.Error(w, "Cross-origin request rejected", 403)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return false
	}
	message := ""
	if r.PostForm.Get("password") != "" || r.PostForm.Get("code") != "" {
		id := strings.TrimPrefix(p.StableSubject(), "local-user:")
		metadata := store.AuditEntry{AuthDecision: string(operatorauth.Authorized), AuthMethod: p.AuthMethod, AuthSubject: p.StableSubject(), AuthCapability: p.GrantedCapabilities.Admin, SourceAddr: b.clientIP.Resolve(r), UserAgent: r.UserAgent()}
		err := b.store.ReauthenticateDiskAdmin(metadata, r.PostForm.Get("password"), r.PostForm.Get("code"), true)
		if err == nil {
			c, e := r.Cookie(localauth.CookieName(b.cloud.public.Scheme() == "https"))
			if e == nil {
				err = b.store.RefreshSessionMFA(c.Value, id)
			} else {
				err = e
			}
		}
		if err == nil {
			p.ActionMFAAuthorized = true
			*r = *operatorauth.WithPrincipal(r, p)
			r.PostForm.Del("password")
			r.PostForm.Del("code")
			r.Form.Del("password")
			r.Form.Del("code")
			return true
		}
		message = "Reauthentication failed; check your current password and authenticator code."
	}
	fields := url.Values{}
	for key, values := range r.PostForm {
		// Never echo factors or account credentials into a challenge.
		lower := strings.ToLower(key)
		if lower == "code" || strings.Contains(lower, "password") || strings.Contains(lower, "secret") || strings.Contains(lower, "token") {
			continue
		}
		fields[key] = values
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = actionMFAForm.Execute(w, struct {
		Why, Error, Action string
		Fields             url.Values
	}{why, message, r.URL.RequestURI(), fields})
	return false
}
