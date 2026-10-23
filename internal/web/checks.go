package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/docs/runbooks"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"time"
)

type checksMachine struct {
	ID, Name string
	Reports  []operator.ReadReport
}
type checksPage struct {
	Machines      []checksMachine
	Targets       []scheduleMachine
	Previews      []schedulePage
	Manage, Admin bool
}

func (s *Server) checksRoutes(mux *http.ServeMux) []string {
	mux.HandleFunc("GET /checks", s.checks)
	mux.HandleFunc("POST /checks/schedules/preview", s.checkSchedulesPreview)
	return []string{"GET /checks", "POST /checks/schedules/preview"}
}
func (s *Server) checks(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, false) {
		return
	}
	list, err := s.scheduleMachines()
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	v := &checksPage{}
	_, v.Manage, v.Admin = scheduleAccess(r)
	// Bounded machine page; retain the existing roster's cursor contract.
	req := operator.MachineListRequest{Limit: 25, Cursor: r.URL.Query().Get("cursor")}
	machines, err := s.operator.ListMachinesPage(req, time.Now().UTC())
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	for _, m := range list.Items {
		if m.RetiredAt == nil {
			v.Targets = append(v.Targets, scheduleMachine{ID: m.MachineID, Name: m.DisplayName, Selected: r.URL.Query().Get("target") == m.MachineID})
		}
	}
	scheduled, err := s.operator.ScheduledCheckReports(time.Now().UTC())
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	for _, m := range machines.Items {
		reports, e := s.operator.MachineReadReports(m.MachineID)
		if e != nil {
			s.scheduleError(w, r, e)
			return
		}
		v.Machines = append(v.Machines, checksMachine{m.MachineID, m.DisplayName, append(scheduled[m.MachineID], reports...)})
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "checks.html", page{Title: "Checks / 檢查", Nav: "checks", Checks: v, ChecksNext: machines.NextCursor})
}
func (s *Server) checkSchedulesPreview(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, true) {
		return
	}
	if !diskOpsForm(w, r, "target") {
		s.scheduleBad(w, r)
		return
	}
	var reqs []store.ScheduleRequest
	if err := json.Unmarshal(runbooks.Phase0Schedules, &reqs); err != nil {
		s.fail(w, "Schedule examples", err)
		return
	}
	v := &checksPage{}
	_, v.Manage, v.Admin = scheduleAccess(r)
	for _, req := range reqs {
		req.Targets = []string{r.PostForm.Get("target")}
		req.Enabled = false
		req.CatchUp = false
		req.TZ = "UTC"
		actor, ok := s.scheduleActor(w, r, req, false)
		if !ok {
			return
		}
		out, err := s.operator.ScheduleManage(req, "upsert", false, "", actor)
		if err != nil {
			s.scheduleError(w, r, err)
			return
		}
		key, err := operator.NewIdempotencyKey("web-check-schedule")
		if err != nil {
			s.fail(w, "Request key", err)
			return
		}
		raw, _ := json.Marshal(req)
		canonical, _ := json.MarshalIndent(req, "", "  ")
		v.Previews = append(v.Previews, schedulePage{Body: string(raw), Canonical: string(canonical), Digest: out.PreviewDigest, Key: key, Edit: req})
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, "check_schedules.html", page{Title: "Set up disabled schedules / 建立停用排程", Nav: "checks", Checks: v})
}
