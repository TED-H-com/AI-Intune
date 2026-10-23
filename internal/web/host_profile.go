package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strconv"
	"time"
)

type hostProfileField struct {
	Name, Label, Value string
	Boolean            bool
}
type hostProfilePage struct {
	Fleet  store.FleetHostProfile
	Fields []hostProfileField
	Manage bool
	Saved  bool
}

func hostProfileFields(p model.HostProfile) []hostProfileField {
	boolField := func(n, l string, v *bool) hostProfileField {
		f := hostProfileField{Name: n, Label: l, Boolean: true}
		if v != nil {
			f.Value = strconv.FormatBool(*v)
		}
		return f
	}
	power, journal := "", ""
	if p.PowerProfile != nil {
		power = *p.PowerProfile
	}
	if p.JournaldMaxMB != nil {
		journal = strconv.Itoa(*p.JournaldMaxMB)
	}
	return []hostProfileField{
		boolField("lid_ignore", "Keep running with the lid closed", p.LidIgnore), boolField("disable_sleep", "Never sleep", p.DisableSleep),
		{Name: "power_profile", Label: "Power mode", Value: power}, boolField("wifi_power_save_off", "Keep Wi-Fi awake", p.WifiPowerSaveOff),
		{Name: "journald_max_mb", Label: "Journal size limit (MB)", Value: journal}, boolField("unattended_upgrades", "Install security updates automatically", p.UnattendedUpgrades),
		boolField("scoped_sudoers", "Allow the agent's scoped admin commands", p.ScopedSudoers), boolField("linger", "Keep user services running after logout", p.Linger), boolField("root_disk_clean_timer", "Clean root disk space daily", p.RootDiskCleanTimer)}
}
func (s *Server) hostProfileRoutes(mux *http.ServeMux) []string {
	routes := []string{"GET /machines/host-profile", "POST /machines/host-profile", "GET /v1/operator/host-profile"}
	for _, route := range routes {
		mux.HandleFunc(route, s.hostProfile)
	}
	return routes
}
func (s *Server) hostProfile(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	if !ok || !p.Has(operatorauth.View) || r.Method == "POST" && !p.Has(operatorauth.Admin) {
		http.Error(w, "Host setup access denied", 403)
		return
	}
	if r.Method == "POST" {
		fields := hostProfileFields(model.HostProfile{})
		allowed := []string{}
		for _, f := range fields {
			allowed = append(allowed, f.Name)
		}
		if !operatorWebForm(w, r, nil, allowed...) {
			http.Error(w, "Invalid form", 400)
			return
		}
		values := map[string]any{}
		for _, f := range fields {
			v := r.PostForm.Get(f.Name)
			if v == "" {
				continue
			}
			if f.Boolean {
				if v != "true" && v != "false" {
					http.Error(w, "Choose a host setting", 400)
					return
				}
				values[f.Name] = v == "true"
			} else if f.Name == "journald_max_mb" {
				n, e := strconv.Atoi(v)
				if e != nil {
					http.Error(w, "Enter a journal size from 100 to 4096 MB", 400)
					return
				}
				values[f.Name] = n
			} else {
				values[f.Name] = v
			}
		}
		raw, _ := json.Marshal(values)
		profile, err := model.ParseHostProfile(raw)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		audit := store.AuditEntry{At: time.Now().UTC()}
		operator.ApplyActor(&audit, operator.ActorFromRequest(r, operator.SourceKindWeb))
		if err = s.store.SaveHostProfile(profile, audit); err != nil {
			s.fail(w, "Unable to save host setup", err)
			return
		}
		http.Redirect(w, r, "/machines/host-profile?saved=1", http.StatusSeeOther)
		return
	}
	fleet, err := s.store.FleetHostProfile(time.Now().UTC())
	if err != nil {
		s.fail(w, "Unable to load host setup", err)
		return
	}
	if r.URL.Path == "/v1/operator/host-profile" {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(fleet)
		return
	}
	s.render(w, r, "host_profile.html", page{Title: "Host setup profile", Nav: "machines-configuration", HostProfile: &hostProfilePage{Fleet: fleet, Fields: hostProfileFields(fleet.Profile), Manage: p.Has(operatorauth.Admin), Saved: r.URL.Query().Get("saved") == "1"}})
}
