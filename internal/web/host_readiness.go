package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"time"
)

type readinessPage struct {
	Items  []store.HostChecklist
	Manage bool
}

func (s *Server) readinessRoutes(mux *http.ServeMux) []string {
	routes := []string{"GET /readiness", "POST /readiness", "GET /v1/operator/machines/{id}/readiness"}
	for _, route := range routes {
		mux.HandleFunc(route, s.hostReadiness)
	}
	return routes
}
func (s *Server) hostReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || !p.Has(operatorauth.View) || r.Method == "POST" && !p.Has(operatorauth.Admin) {
		http.Error(w, "Readiness access denied", 403)
		return
	}
	id := r.PathValue("id")
	if id == "" {
		id = r.URL.Query().Get("machine")
	}
	if r.Method == "POST" {
		if !operatorWebForm(w, r, nil, "machine", "path", "sudoers_path", "backup_unit") {
			http.Error(w, "Invalid form", 400)
			return
		}
		id = r.PostForm.Get("machine")
		if _, err := s.store.HostChecklist(id, time.Now().UTC()); err != nil {
			http.NotFound(w, r)
			return
		}
		audit := store.AuditEntry{At: time.Now().UTC()}
		operator.ApplyActor(&audit, operator.ActorFromRequest(r, operator.SourceKindWeb))
		err := s.store.SaveHostReadinessConfig(id, model.ReadinessConfig{Path: r.PostForm.Get("path"), SudoersPath: r.PostForm.Get("sudoers_path"), BackupUnit: r.PostForm.Get("backup_unit")}, audit)
		if err != nil {
			http.Error(w, "Invalid readiness targets: choose an access path, /etc/sudoers.d/name, and a backup .service unit", 400)
			return
		}
		http.Redirect(w, r, "/readiness?machine="+id, http.StatusSeeOther)
		return
	}
	view := &readinessPage{Manage: p.Has(operatorauth.Admin)}
	if id != "" {
		item, err := s.store.HostChecklist(id, time.Now().UTC())
		if err != nil {
			http.NotFound(w, r)
			return
		}
		view.Items = append(view.Items, item)
	} else {
		ov, err := s.store.Overview(time.Now().UTC())
		if err != nil {
			s.fail(w, "Unable to load readiness", err)
			return
		}
		for _, m := range ov.Machines {
			item, err := s.store.HostChecklist(m.MachineID, time.Now().UTC())
			if err != nil {
				s.fail(w, "Unable to load readiness", err)
				return
			}
			view.Items = append(view.Items, item)
		}
	}
	if r.PathValue("id") != "" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(view.Items[0])
		return
	}
	s.render(w, r, "readiness.html", page{Title: "Host readiness", Nav: "machines", Readiness: view})
}
