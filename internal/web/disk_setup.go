package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/url"
	"time"
)

type diskSetupPage struct {
	Machine   string
	Inventory store.MachineDisks
	Manage    bool
	Owner     string
	Error     string
}

func (s *Server) diskSetupRoutes(mux *http.ServeMux) []string {
	routes := []string{"POST /machines/{id}/disks/approve", "POST /machines/{id}/disks/cancel", "GET /v1/operator/machines/{id}/disks"}
	for _, route := range routes {
		mux.HandleFunc(route, s.diskSetup)
	}
	return routes
}
func (s *Server) diskSetup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || !p.Has(operatorauth.View) || r.Method == "POST" && !humanWebAdmin(r) {
		http.Error(w, "Disk setup access denied", 403)
		return
	}
	if r.Method == "POST" && p.AuthMethod == operatorauth.AuthMethodLocalAccountSession && !p.ActionMFAAuthorized && !operatorauth.MFAWithin(p.MFAVerifiedAt, time.Now(), operatorauth.DangerousMFAWindow) {
		http.Error(w, "Fresh MFA is required to approve disk setup", 403)
		return
	}
	id := r.PathValue("id")
	inventory, err := s.store.MachineDisks(id)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if r.Method == "GET" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inventory)
		return
	}
	if !operatorWebForm(w, r, nil, "device", "mount_point", "fstype", "label", "owner", "job_id", "confirm") {
		http.Error(w, "Invalid disk setup form", 400)
		return
	}
	audit := store.AuditEntry{At: time.Now().UTC()}
	operator.ApplyActor(&audit, operator.ActorFromRequest(r, operator.SourceKindWeb))
	if r.URL.Path == "/machines/"+id+"/disks/cancel" {
		err = s.store.CancelDiskSetup(id, r.PostForm.Get("job_id"), audit)
	} else {
		var job model.DiskJob
		for _, d := range inventory.Devices {
			if d.Path == r.PostForm.Get("device") && model.UnusedDisk(d) {
				job = model.DiskJob{Device: d.Path, Serial: d.Serial, WWN: d.WWN, SizeBytes: d.SizeBytes, Model: d.Model}
				break
			}
		}
		job.MountPoint = r.PostForm.Get("mount_point")
		job.FSType = r.PostForm.Get("fstype")
		job.Label = r.PostForm.Get("label")
		job.Owner = r.PostForm.Get("owner")
		if r.PostForm.Get("confirm") != "yes" {
			err = store.ErrNotFound
		} else {
			_, err = s.store.ApproveDiskSetup(id, job, audit)
		}
	}
	if err != nil {
		s.renderActionStatus(w, r, 400, "Disk setup", "Disk setup was not approved", err.Error(), "/machines/"+url.PathEscape(id)+"#disks")
		return
	}
	http.Redirect(w, r, "/machines/"+url.PathEscape(id)+"#disks", http.StatusSeeOther)
}
