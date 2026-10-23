package main

import (
	"github.com/teddashh/AI-Intune/internal/totp"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func TestActionMFAWindowBoundary(t *testing.T) {
	for _, tc := range []struct {
		name, pattern string
		age, window   time.Duration
		want          bool
	}{
		{"routine login MFA", "POST /v1/operator/deployments", time.Hour, 0, true},
		{"expired", "POST /v1/operator/deployments", 13 * time.Hour, 0, false},
		{"configured shorter", "POST /v1/operator/deployments", 2 * time.Hour, time.Hour, false},
		{"configured longer", "POST /v1/operator/deployments", 13 * time.Hour, 24 * time.Hour, true},
		{"dangerous stale", "DELETE /v1/operator/machines/{id}", 6 * time.Minute, 24 * time.Hour, false},
		{"dangerous fresh", "DELETE /v1/operator/machines/{id}", time.Minute, 24 * time.Hour, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := &operatorBoundary{cloud: &cloudBoundaryConfig{requireMFA: true, adminMFAWindow: tc.window}}
			r := httptest.NewRequest("POST", "https://hub.example.com/action", strings.NewReader("reason=rotate+disk+on+sampleagent1%2C+per+ticket+%2342&preview_digest=abc&idempotency_key=retry-key&password=&code="))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r = operatorauth.WithPrincipal(r, operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession, MFAVerifiedAt: time.Now().Add(-tc.age)})
			w := httptest.NewRecorder()
			got := b.authorizeActionMFA(w, r, tc.pattern, operatorRoutePolicy{Permission: operatorauth.Admin, Representation: operatorHTML})
			if got != tc.want {
				t.Fatalf("allowed=%v status=%d", got, w.Code)
			}
			if got {
				p, _ := operatorauth.PrincipalFromContext(r.Context())
				if !p.ActionMFAAuthorized {
					t.Fatal("missing action proof")
				}
			} else {
				for _, want := range []string{"Confirm your identity", `name="reason" value="rotate disk on sampleagent1, per ticket #42"`, `name="preview_digest" value="abc"`, `name="idempotency_key" value="retry-key"`} {
					if !strings.Contains(w.Body.String(), want) {
						t.Errorf("missing preserved field %s", want)
					}
				}
			}
		})
	}
}

func TestActionMFAJSONAndCrossOrigin(t *testing.T) {
	b := &operatorBoundary{cloud: &cloudBoundaryConfig{requireMFA: true}}
	for _, representation := range []operatorRepresentation{operatorJSON, operatorHTML} {
		r := httptest.NewRequest("POST", "https://hub.example.com/action", strings.NewReader("reason=maintenance"))
		r.Header.Set("Origin", "https://attacker.example")
		r = operatorauth.WithPrincipal(r, operatorauth.Principal{AuthMethod: operatorauth.AuthMethodLocalAccountSession})
		w := httptest.NewRecorder()
		if b.authorizeActionMFA(w, r, "POST /v1/operator/deployments", operatorRoutePolicy{Permission: operatorauth.Admin, Representation: representation}) || w.Code != 403 {
			t.Fatal("missing MFA accepted")
		}
		if representation == operatorJSON && !strings.Contains(w.Body.String(), "MFA_STEP_UP_REQUIRED") {
			t.Fatal("missing explicit code")
		}
		if representation == operatorHTML && strings.Contains(w.Body.String(), "maintenance") {
			t.Fatal("cross-origin form echoed")
		}
	}
}

func TestAdminMFAConfiguration(t *testing.T) {
	unsetMFARequirement(t)
	t.Setenv("CLAWCTL_PUBLIC_URL", "https://hub.example.com")
	for _, raw := range []string{"2h", "24h", "0", "-1h", "invalid"} {
		t.Setenv("CLAWCTL_ADMIN_MFA_WINDOW", raw)
		c, err := cloudConfiguration(authModeLocal, "127.0.0.1:8787")
		d, e := time.ParseDuration(raw)
		if e != nil || d <= 0 {
			if err == nil {
				t.Fatal("invalid duration accepted")
			}
		} else if err != nil || c.adminMFAWindow != d {
			t.Fatal("configuration ignored", err)
		}
	}
}

func TestActionMFARoundTrip(t *testing.T) {
	unsetMFARequirement(t)
	h, st := localAccountHandler(t)
	a, err := st.CreateFirstAdmin("admin", "a long test password")
	if err != nil {
		t.Fatal(err)
	}
	w := accountRequest(h, "POST", "/login", "username=admin&password=a+long+test+password", nil)
	session := w.Result().Cookies()[0]
	secret, err := st.BeginTOTPEnrollment(a.AccountID)
	if err != nil {
		t.Fatal(err)
	}
	// Enroll with the preceding slot so the current slot remains available for step-up.
	code, _ := totp.Code(secret, time.Now().Unix()/30-1)
	if _, err = st.ConfirmTOTPForSession(a.AccountID, code, session.Value); err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`UPDATE hub_sessions SET mfa_verified_at=?`, time.Now().Add(-13*time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	reason := "rotate disk on sampleagent1, per ticket #42"
	body := "reason=" + url.QueryEscape(reason) + "&idempotency_key=retry-key"
	// An invalid operation is intentional: the handler must receive the original
	// inputs after step-up rather than dispatching any actual fleet work.
	w = accountRequest(h, "POST", "/tenant/schedules/preview", body, session)
	if w.Code != 403 || !strings.Contains(w.Body.String(), reason) {
		t.Fatalf("challenge did not preserve reason: %d", w.Code)
	}
	code, _ = totp.Code(secret, time.Now().Unix()/30)
	w = accountRequest(h, "POST", "/tenant/schedules/preview", body+"&password=a+long+test+password&code="+code, session)
	if strings.Contains(w.Body.String(), "Reauthentication failed") || strings.Contains(w.Body.String(), "Your admin MFA window has expired") {
		t.Fatalf("step-up did not complete: %d", w.Code)
	}
	got, err := st.LookupSession(session.Value)
	if err != nil || !operatorauth.MFAWithin(got.SessionMFAVerifiedAt, time.Now(), time.Minute) {
		t.Fatal("step-up proof not persisted", err)
	}
}
