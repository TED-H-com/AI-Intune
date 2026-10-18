package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"sort"
	"strings"
	"time"
)

type readinessPage struct {
	Items                []store.HostChecklist
	Manage               bool
	Fleet                model.FleetReadinessProfile
	Summary              []readinessGroup
	NeedsYou, Auto, Done int
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
		if !operatorWebForm(w, r, map[string]bool{"expected_clis": true}, "scope", "machine", "path", "sudoers_path", "backup_unit", "expected_clis", "expected_user_units", "auto_remediate") {
			http.Error(w, "Invalid form", 400)
			return
		}
		if r.PostForm.Get("scope") == "fleet" {
			audit := store.AuditEntry{At: time.Now().UTC()}
			operator.ApplyActor(&audit, operator.ActorFromRequest(r, operator.SourceKindWeb))
			profile := model.FleetReadinessProfile{Path: r.PostForm.Get("path"), SudoersPath: r.PostForm.Get("sudoers_path"), BackupUnit: r.PostForm.Get("backup_unit"), ExpectedCLIs: r.PostForm["expected_clis"], ExpectedUserUnits: strings.Fields(r.PostForm.Get("expected_user_units")), AutoRemediateUserUnits: r.PostForm.Get("auto_remediate") == "on"}
			if err := s.store.SaveFleetReadinessProfile(profile, audit); err != nil {
				http.Error(w, "Invalid fleet defaults: check access path, scoped drop-in, CLI names and user unit names (maximum 16).", 400)
				return
			}
			http.Redirect(w, r, "/readiness", http.StatusSeeOther)
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
		ids, err := s.store.ReadinessMachineIDs()
		if err != nil {
			s.fail(w, "Unable to load readiness", err)
			return
		}
		for _, machineID := range ids {
			item, err := s.store.HostChecklist(machineID, time.Now().UTC())
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
	var err error
	view.Fleet, err = s.store.FleetReadinessProfile()
	if err != nil {
		s.fail(w, "Unable to load fleet defaults", err)
		return
	}
	view.group()
	s.render(w, r, "readiness.html", page{Title: "Host readiness", Nav: "machines", Readiness: view})
}

type readinessHost struct{ ID, Name string }
type readinessGroup struct {
	Key, Name, Action, Bucket string
	Hosts                     []readinessHost
}

func (v *readinessPage) group() {
	groups := map[string]*readinessGroup{}
	for _, host := range v.Items {
		v.NeedsYou += host.NeedsYou
		v.Auto += host.Auto
		v.Done += host.Done
		for _, item := range host.Items {
			key := item.Bucket + ":" + item.Key
			g := groups[key]
			if g == nil {
				g = &readinessGroup{Key: item.Key, Name: item.Name, Action: item.NextAction, Bucket: item.Bucket}
				groups[key] = g
			}
			g.Hosts = append(g.Hosts, readinessHost{host.MachineID, host.DisplayName})
		}
	}
	keys := make([]string, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v.Summary = append(v.Summary, *groups[k])
	}
}
