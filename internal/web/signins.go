package web

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"net/http"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

type signinSessionView struct {
	store.SigninSession
	DisplayName string
	Update      model.SigninUpdate
	Active      bool
	MonitorOnly bool
}
type signinsPage struct {
	Channels            []string
	NotificationChannel string
	Groups, Healthy     []store.SigninGroup
	Sessions            []signinSessionView
	Manage, Active      bool
	MonitorOnly         bool
	Needs               int
}

func (s *Server) signinRoutes(mux *http.ServeMux) []string {
	routes := []string{"GET /signins", "GET /v1/operator/signins", "POST /signins/start", "POST /signins/{session}/code", "POST /signins/{session}/cancel", "POST /signins/notifications"}
	mux.HandleFunc(routes[0], s.signinsPage)
	mux.HandleFunc(routes[1], s.signinsPage)
	for _, route := range routes[2:] {
		guard := http.NewCrossOriginProtection().Handler(http.HandlerFunc(s.signinMutation))
		mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			guard.ServeHTTP(w, r)
		})
	}
	return routes
}
func (s *Server) signinsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessFromRequest(r).CanView {
		http.Error(w, "View access required", 403)
		return
	}
	groups, e := s.operator.Signins()
	if e != nil {
		http.Error(w, "Sign-ins are unavailable", 500)
		return
	}
	if r.URL.Path == "/v1/operator/signins" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(groups)
		return
	}
	_ = s.store.ExpireSignins()
	view := &signinsPage{Manage: humanWebAdmin(r)}
	configs, _ := s.store.Channels()
	for _, c := range configs {
		view.Channels = append(view.Channels, c.ID)
	}
	view.NotificationChannel, _ = s.store.SigninNotificationChannel()
	for _, g := range groups {
		healthy := true
		for _, h := range g.Hosts {
			if h.Status != "ok" {
				healthy = false
			}
		}
		view.Needs += g.Needs
		if healthy {
			view.Healthy = append(view.Healthy, g)
		} else {
			view.Groups = append(view.Groups, g)
		}
	}
	sessions, e := s.store.SigninSessions()
	if e != nil {
		http.Error(w, "Sign-ins are unavailable", 500)
		return
	}
	for _, v := range sessions {
		if v.CreatedAt.Before(time.Now().Add(-15 * time.Minute)) {
			continue
		}
		monitorOnly := s.store.MachineExecutionAllowed(v.MachineID) != nil
		active := !monitorOnly && (v.State == "pending" || v.State == "started" || v.State == "waiting_for_code" || v.State == "submitted")
		view.Active = view.Active || active
		// Login URLs and device codes are only shown to a human administrator.
		u := model.SigninUpdate{}
		if view.Manage && !monitorOnly {
			u = s.store.SigninDisplay(v.ID)
		}
		view.Sessions = append(view.Sessions, signinSessionView{v, s.store.DisplayName(v.MachineID), u, active, monitorOnly})
	}
	s.render(w, r, "signins.html", page{Title: "Sign-ins", Nav: "signins", Signins: view})
}
func (s *Server) signinMutation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !humanWebAdmin(r) {
		http.Error(w, "Admin access required", 403)
		return
	}
	p, _ := operatorauth.PrincipalFromContext(r.Context())
	if p.AuthMethod == operatorauth.AuthMethodLocalAccountSession && !p.ActionMFAAuthorized && !operatorauth.MFAWithin(p.MFAVerifiedAt, time.Now(), operatorauth.DangerousMFAWindow) {
		http.Error(w, "Confirm your identity with fresh MFA first", 403)
		return
	}
	if r.Header.Get("Origin") == "" && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "Same-origin form required", 403)
		return
	}
	if !operatorWebForm(w, r, map[string]bool{"target": true}, "target", "session", "signin_code", "channel") {
		http.Error(w, "Invalid sign-in form", 400)
		return
	}
	a := store.AuditEntry{}
	operator.ApplyActor(&a, operator.ActorFromRequest(r, operator.SourceKindWeb))
	if r.URL.Path == "/signins/notifications" {
		if e := s.store.SetSigninNotificationChannel(r.Context(), r.PostForm.Get("channel"), a); e != nil {
			http.Error(w, "Choose an available channel", 400)
			return
		}
	} else if r.URL.Path == "/signins/start" {
		// Targets are opaque row references resolved against the canonical summary,
		// never arbitrary commands, paths, CLI names or account-home directories.
		targets := r.PostForm["target"]
		if len(targets) == 0 || len(targets) > 50 {
			http.Error(w, "Choose a machine", 400)
			return
		}
		groups, e := s.operator.Signins()
		if e != nil {
			http.Error(w, "Sign-ins are unavailable", 500)
			return
		}
		for _, target := range targets {
			found := false
			for _, g := range groups {
				for _, h := range g.Hosts {
					if target == signinTarget(h) {
						v, e := s.store.StartSignin(r.Context(), h.MachineID, h.CLI, h.Slot, a)
						if e != nil {
							http.Error(w, "A sign-in is already active or this machine cannot sign in from the Hub", 409)
							return
						}
						found = true
						s.store.DispatchSignins(v.MachineID)
					}
				}
			}
			if !found {
				http.Error(w, "Sign-in target not found; refresh this page", 400)
				return
			}
		}
	} else {
		id := r.PathValue("session")
		op := "cancel"
		if r.URL.Path == "/signins/"+id+"/code" {
			op = "code"
		}
		code := r.PostForm.Get("signin_code")
		r.PostForm.Del("signin_code")
		r.Form.Del("signin_code")
		if e := s.store.SigninAction(r.Context(), id, op, code, a); e != nil {
			http.Error(w, "This sign-in has ended or the code was already sent", 409)
			return
		}
		sessions, _ := s.store.SigninSessions()
		for _, v := range sessions {
			if v.ID == id {
				s.store.DispatchSignins(v.MachineID)
				break
			}
		}
	}
	http.Redirect(w, r, "/signins", http.StatusSeeOther)
}
func signinTarget(h store.SigninHost) string {
	return h.MachineID + ":" + h.CLI + ":" + string(rune('0'+h.Slot))
}

func signinLabel(state string) string {
	labels := map[string]string{"pending": "Queued", "started": "Signing in", "waiting_for_code": "Waiting for your code", "submitted": "Code sent", "done": "Completed", "failed": "Could not sign in", "expired": "Timed out", "cancelled": "Cancelled", "ok": "Signed in", "expiring": "Expires soon", "logged_out": "Signed out", "failing": "Recent sign-in failure", "unknown": "Unknown"}
	if label, ok := labels[state]; ok {
		return label
	}
	return "Unknown"
}

func signinNeeds(status string) bool {
	return status == "logged_out" || status == "failing" || status == "expiring"
}

// SigninRefreshScript pauses reloads while a pasted code is being entered.
const SigninRefreshScript = `setInterval(function () {
  const inputs = document.querySelectorAll('input[name="signin_code"]');
  for (const input of inputs) {
    if (input === document.activeElement || input.value.length > 0) return;
  }
  window.location.reload();
}, 5000);`

func SigninRefreshScriptHash() string {
	sum := sha256.Sum256([]byte(SigninRefreshScript))
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func init() {
	funcs["signinRefreshScript"] = func() template.JS { return template.JS(SigninRefreshScript) }
}
