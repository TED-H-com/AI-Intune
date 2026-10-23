package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/chat"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

type channelRow struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}
type channelsView struct {
	Inbound   []chat.Status          `json:"inbound"`
	Allowlist []store.ChatUser       `json:"allowlist,omitempty"`
	Approvals []store.ChatApproval   `json:"approvals"`
	Bots      []store.ChannelBot     `json:"bots"`
	Rows      []channelRow           `json:"channels"`
	Bindings  []store.ChannelBinding `json:"bindings"`
}

func (s *Server) channelRoutes(mux *http.ServeMux) []string {
	mux.HandleFunc("GET /channels", s.channelsPage)
	mux.HandleFunc("GET /v1/operator/channels", s.channelsPage)
	mux.Handle("POST /channels/{operation}", http.NewCrossOriginProtection().Handler(http.HandlerFunc(s.channelMutation)))
	return []string{"GET /channels", "GET /v1/operator/channels", "POST /channels/{operation}"}
}
func (s *Server) channelsPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessFromRequest(r).CanView {
		http.Error(w, "forbidden", 403)
		return
	}
	configs, e := s.store.Channels()
	if e != nil {
		http.Error(w, "channels unavailable", 500)
		return
	}
	view := channelsView{Rows: []channelRow{}}
	if s.inbound != nil {
		view.Inbound = s.inbound.Status()
	}
	if accessFromRequest(r).CanAdmin {
		view.Allowlist, e = s.store.ChatUsers()
		if e != nil {
			http.Error(w, "allowlist unavailable", 500)
			return
		}
	}
	view.Approvals, e = s.store.PendingChatApprovals(time.Now())
	if e != nil {
		http.Error(w, "approvals unavailable", 500)
		return
	}
	for _, c := range configs {
		status, _ := channels.New(c, s.secretProvider).Health(r.Context())
		view.Rows = append(view.Rows, channelRow{c.ID, c.Kind, string(status)})
	}
	view.Bindings, e = s.store.ChannelBindings()
	if e != nil {
		http.Error(w, "bindings unavailable", 500)
		return
	}
	view.Bots, e = s.store.ChannelBots()
	if e != nil {
		http.Error(w, "bots unavailable", 500)
		return
	}
	if r.URL.Path == "/v1/operator/channels" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view)
		return
	}
	s.render(w, r, "channels.html", page{Title: "Channels", Nav: "channels", Channels: &view})
}
func (s *Server) channelMutation(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !accessFromRequest(r).CanAdmin {
		http.Error(w, "forbidden", 403)
		return
	}
	// Require browser origin evidence as well as CrossOriginProtection.
	// Requests without either header fail closed.
	if r.Header.Get("Origin") == "" && r.Header.Get("Sec-Fetch-Site") != "same-origin" {
		http.Error(w, "origin required", http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if e := r.ParseForm(); e != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	c := channels.Config{ID: r.FormValue("id"), Kind: r.FormValue("kind"), TokenRef: r.FormValue("token_ref"), ChatRef: r.FormValue("chat_ref"), URLRef: r.FormValue("url_ref"), SecretRef: r.FormValue("secret_ref")}
	a := store.AuditEntry{}
	operator.ApplyActor(&a, operator.ActorFromRequest(r, operator.SourceKindWeb))
	op := r.PathValue("operation")
	if op == "allow-save" || op == "allow-remove" {
		u := store.ChatUser{ChannelID: r.FormValue("id"), UserID: r.FormValue("user_id"), AccountID: r.FormValue("account_id")}
		if e := s.store.MutateChatUser(r.Context(), u, op == "allow-remove", a); e != nil {
			http.Error(w, "allowlist update failed", 400)
			return
		}
		http.Redirect(w, r, "/channels", 303)
		return
	}
	if op == "bot-save" || op == "bot-remove" {
		b := store.ChannelBot{Name: r.FormValue("name"), Kind: c.Kind, MachineID: r.FormValue("machine_id"), AgentType: r.FormValue("agent_type"), TokenRef: c.TokenRef, Status: r.FormValue("status"), Notes: r.FormValue("notes")}
		if e := s.store.MutateChannelBot(r.Context(), op[4:], b, a); e != nil {
			http.Error(w, "bot update failed; check metadata and references", 400)
			return
		}
		http.Redirect(w, r, "/channels", 303)
		return
	}
	if op == "test" {
		configs, e := s.store.Channels()
		if e != nil {
			http.Error(w, "channels unavailable", 500)
			return
		}
		for _, config := range configs {
			if config.ID == c.ID {
				if e = s.operator.TestChannel(r.Context(), config, s.secretProvider, operator.ActorFromRequest(r, operator.SourceKindWeb)); e != nil {
					http.Error(w, "test delivery failed", 502)
					return
				}

				http.Redirect(w, r, "/channels", 303)
				return
			}
		}
		http.Error(w, "channel not found", 404)
		return
	}
	if e := s.store.MutateChannel(r.Context(), op, c, r.FormValue("machine_id"), a); e != nil {
		http.Error(w, "channel update failed; check identifiers and credential references", 400)
		return
	}
	http.Redirect(w, r, "/channels", 303)
}

// ConfigureInbound installs the explicitly enabled provider front ends.
func (s *Server) ConfigureInbound(path string) error {
	cs, e := chat.Load(path)
	if e != nil {
		return e
	}
	s.inbound = chat.New(cs, s.store, s.operator, s.secretProvider)
	return nil
}
func (s *Server) InboundRoutes(mux *http.ServeMux) []string {
	const pattern = "POST /v1/channels/{id}/inbound"
	mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		if s.inbound == nil {
			http.NotFound(w, r)
			return
		}
		s.inbound.ServeHTTP(w, r)
	})
	return []string{pattern}
}
