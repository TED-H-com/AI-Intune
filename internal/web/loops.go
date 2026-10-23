package web

import (
	"net/http"
	"strconv"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

type loopsPage struct {
	Policy  store.LoopPolicy
	Items   []store.LoopEpisode
	Machine string
}

func (s *Server) loopRoutes(mux *http.ServeMux) []string {
	mux.HandleFunc("GET /attention/loops", s.loops)
	mux.HandleFunc("POST /attention/loops", s.loopAction)
	return []string{"GET /attention/loops", "POST /attention/loops"}
}
func (s *Server) loops(w http.ResponseWriter, r *http.Request) {
	machine := r.URL.Query().Get("machine_id")
	items, err := s.store.LoopEpisodes(machine)
	if err != nil {
		s.fail(w, "Unable to load loops", err)
		return
	}
	policy, err := s.store.LoopPolicy()
	if err != nil {
		s.fail(w, "Unable to load loop policy", err)
		return
	}
	s.render(w, r, "loops.html", page{Title: "Attention / Loops", Nav: "loops", Loops: &loopsPage{Policy: policy, Items: items, Machine: machine}})
}
func (s *Server) loopAction(w http.ResponseWriter, r *http.Request) {
	if !humanWebAdmin(r) {
		http.Error(w, "Human administrator required", 403)
		return
	}
	if !operatorWebForm(w, r, nil, "action", "id", "threshold", "window_seconds") {
		http.Error(w, "Invalid form", 400)
		return
	}
	var err error
	switch r.PostForm.Get("action") {
	case "policy":
		threshold, e1 := strconv.Atoi(r.PostForm.Get("threshold"))
		window, e2 := strconv.Atoi(r.PostForm.Get("window_seconds"))
		if e1 != nil || e2 != nil {
			http.Error(w, "Invalid policy", 400)
			return
		}
		err = s.store.SetLoopPolicy(store.LoopPolicy{Threshold: threshold, WindowSeconds: window})
	case "acknowledge", "resolve":
		id, e := strconv.ParseInt(r.PostForm.Get("id"), 10, 64)
		if e != nil || id < 1 {
			http.Error(w, "Invalid episode", 400)
			return
		}
		err = s.store.LoopDecision(id, r.PostForm.Get("action") == "resolve", time.Now().UTC())
	default:
		http.Error(w, "Invalid action", 400)
		return
	}
	if err != nil {
		s.renderActionStatus(w, r, 400, "Loops", "Unable to update loop evidence", "Check the policy bounds or reload the episode.", "/attention/loops")
		return
	}
	http.Redirect(w, r, "/attention/loops", http.StatusSeeOther)
}
