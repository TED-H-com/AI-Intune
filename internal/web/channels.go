package web

import (
	"encoding/json"
	"net/http"

	"github.com/teddashh/AI-Intune/internal/channels"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

type channelRow struct {
	ID     string `json:"id"`
	Kind   string `json:"kind"`
	Status string `json:"status"`
}
type channelsView struct {
	Rows     []channelRow           `json:"channels"`
	Bindings []store.ChannelBinding `json:"bindings"`
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
	for _, c := range configs {
		status, _ := channels.New(c, s.secretProvider).Health(r.Context())
		view.Rows = append(view.Rows, channelRow{c.ID, c.Kind, string(status)})
	}
	view.Bindings, e = s.store.ChannelBindings()
	if e != nil {
		http.Error(w, "bindings unavailable", 500)
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
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if e := r.ParseForm(); e != nil {
		http.Error(w, "invalid form", 400)
		return
	}
	c := channels.Config{ID: r.FormValue("id"), Kind: r.FormValue("kind"), TokenRef: r.FormValue("token_ref"), ChatRef: r.FormValue("chat_ref"), URLRef: r.FormValue("url_ref"), SecretRef: r.FormValue("secret_ref")}
	a := store.AuditEntry{}
	operator.ApplyActor(&a, operator.ActorFromRequest(r, operator.SourceKindWeb))
	op := r.PathValue("operation")
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
