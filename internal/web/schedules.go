package web

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/schedulecron"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
)

const schedulesBack = "/tenant/schedules"

type scheduleRow struct {
	store.Schedule
	TargetsLabel, NextLocal, NextUTC string
	Results                          []operator.JobSummary
	ExecutionBlocked                 bool
}
type scheduleMachine struct {
	ID, Name string
	Selected bool
}
type scheduleScript struct {
	scriptcatalog.Entry
	Selected bool
	Schema   string
}
type schedulePage struct {
	Items                                          []scheduleRow
	Selected                                       *scheduleRow
	Edit                                           store.ScheduleRequest
	Machines                                       []scheduleMachine
	Scripts                                        []scheduleScript
	Zones                                          []string
	Error, Body, Canonical, Operation, Digest, Key string
	Times                                          []string
	Manage, Admin, Confirm, RunNow                 bool
	Jobs                                           []scheduleJob
}
type scheduleJob struct {
	operator.JobSummary
	Exit, Duration string
}

func (s *Server) scheduleRoutes(mux *http.ServeMux) []string {
	routes := []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /tenant/schedules", s.schedules}, {"GET /tenant/schedules/new", s.scheduleForm},
		{"GET /tenant/schedules/{id}", s.scheduleDetail}, {"GET /tenant/schedules/{id}/edit", s.scheduleForm},
		{"POST /tenant/schedules/preview", s.schedulePreview}, {"POST /tenant/schedules/apply", s.scheduleApply},
		{"POST /tenant/schedules/{id}/run-now", s.scheduleRunNow},
	}
	out := []string{}
	for _, r := range routes {
		mux.HandleFunc(r.pattern, r.handler)
		out = append(out, r.pattern)
	}
	return out
}
func scheduleAccess(r *http.Request) (bool, bool, bool) {
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	return ok && p.Has(operatorauth.View), ok && p.Has(operatorauth.Operate), ok && p.Has(operatorauth.Admin)
}
func (s *Server) scheduleAllowed(w http.ResponseWriter, r *http.Request, manage bool) bool {
	if manage && r.Method == http.MethodPost && s.scheduleAdmission != nil && !s.scheduleAdmission(w, r) {
		return false
	}
	view, operate, _ := scheduleAccess(r)
	if !view || manage && !operate {
		s.renderActionStatus(w, r, 403, "Schedules", "權限不足", "檢視需要 View；管理需要 Operate。", schedulesBack)
		return false
	}
	return true
}
func (s *Server) scheduleRender(w http.ResponseWriter, r *http.Request, name string, v *schedulePage) {
	w.Header().Set("Cache-Control", "no-store")
	_, v.Manage, v.Admin = scheduleAccess(r)
	s.render(w, r, name, page{Title: "Schedules", Nav: "tenant-schedules", Schedules: v})
}
func (s *Server) scheduleError(w http.ResponseWriter, r *http.Request, err error) {
	status, _, detail := operator.HTTPError(err)
	if errors.Is(err, sql.ErrNoRows) {
		status = http.StatusNotFound
		detail = "Schedule not found"
	}
	s.renderActionStatus(w, r, status, "Schedules", "排程操作失敗", detail, schedulesBack)
}
func (s *Server) scheduleBad(w http.ResponseWriter, r *http.Request) {
	action := scheduleAuditAction(r)
	if err := s.operator.RejectScheduleTransport(operator.ActorFromRequest(r, operator.SourceKindWeb), action); err != nil {
		s.fail(w, "Audit", err)
		return
	}
	s.renderActionStatus(w, r, 400, "Schedules", "表單不合法", "請返回重新預覽。", schedulesBack)
}
func (s *Server) scheduleRow(v store.Schedule, names map[string]string) (scheduleRow, error) {
	row := scheduleRow{Schedule: v}
	labels := []string{}
	for _, id := range v.Targets {
		if s.store.MachineExecutionAllowed(id) != nil {
			row.ExecutionBlocked = true
		}
		name := names[id]
		if name == "" {
			name = id
		}
		labels = append(labels, name)
	}
	row.TargetsLabel = strings.Join(labels, ", ")
	loc, err := time.LoadLocation(v.TZ)
	if err != nil {
		return row, err
	}
	row.NextLocal = v.NextRunAt.In(loc).Format("2006-01-02 15:04 MST")
	row.NextUTC = v.NextRunAt.UTC().Format(time.RFC3339)
	for _, id := range v.LastJobIDs {
		job, err := s.operator.JobDetail(id, time.Now().UTC())
		if err != nil {
			return row, err
		}
		row.Results = append(row.Results, job.Item)
	}
	return row, nil
}
func (s *Server) scheduleNames() (map[string]string, error) {
	list, err := s.scheduleMachines()
	names := map[string]string{}
	for _, m := range list.Items {
		names[m.MachineID] = m.DisplayName
	}
	return names, err
}
func (s *Server) schedules(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, false) {
		return
	}
	items, err := s.operator.Schedules()
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	names, err := s.scheduleNames()
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	v := &schedulePage{}
	for _, item := range items {
		row, err := s.scheduleRow(item, names)
		if err != nil {
			s.scheduleError(w, r, err)
			return
		}
		v.Items = append(v.Items, row)
	}
	s.scheduleRender(w, r, "schedules.html", v)
}
func (s *Server) scheduleEditView(req store.ScheduleRequest) (*schedulePage, error) {
	v := &schedulePage{Edit: req}
	list, err := s.scheduleMachines()
	if err != nil {
		return nil, err
	}
	for _, m := range list.Items {
		if m.RetiredAt != nil || s.store.MachineExecutionAllowed(m.MachineID) != nil {
			continue
		}
		selected := false
		for _, id := range req.Targets {
			if id == m.MachineID {
				selected = true
			}
		}
		v.Machines = append(v.Machines, scheduleMachine{m.MachineID, m.DisplayName, selected})
	}
	for _, entry := range scriptcatalog.List() {
		schema, _ := json.MarshalIndent(entry.ArgsSchema, "", "  ")
		v.Scripts = append(v.Scripts, scheduleScript{Entry: entry, Selected: entry.ID == req.ScriptID, Schema: string(schema)})
	}
	v.Zones = scheduleZones(req.TZ)
	return v, nil
}
func scheduleZones(selected string) []string {
	// Use the system IANA database; Go validates every submitted value separately.
	zones := []string{"America/New_York", "UTC"}
	seen := map[string]bool{"America/New_York": true, "UTC": true}
	for _, zone := range ianaZones {
		if !seen[zone] {
			zones = append(zones, zone)
			seen[zone] = true
		}
	}
	if selected != "" && !seen[selected] {
		zones = append(zones, selected)
	}
	return zones
}
func (s *Server) scheduleForm(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, true) {
		return
	}
	req := store.ScheduleRequest{ScriptID: "fleet-probe-v2", Args: json.RawMessage(`{}`), TZ: "America/New_York", Cron: "0 12 * * *", Enabled: true}
	if id := r.PathValue("id"); id != "" {
		v, err := s.operator.Schedule(id)
		if err != nil {
			s.scheduleError(w, r, err)
			return
		}
		req = store.ScheduleRequest{ID: v.ID, Name: v.Name, ScriptID: v.ScriptID, ScriptSHA256: v.ScriptSHA256, Args: v.Args, Targets: v.Targets, Cron: v.Cron, TZ: v.TZ, Enabled: v.Enabled, ExpectedRevision: v.Revision}
	}
	v, err := s.scheduleEditView(req)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	s.scheduleRender(w, r, "schedule_form.html", v)
}
func scheduleDecode(raw string, req *store.ScheduleRequest) error {
	d := json.NewDecoder(strings.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(req); err != nil {
		return err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid request JSON")
	}
	return nil
}
func (s *Server) scheduleActor(w http.ResponseWriter, r *http.Request, req store.ScheduleRequest, apply bool) (operator.Actor, bool) {
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	p, _ := operatorauth.PrincipalFromContext(r.Context())
	write := false
	if entry, ok := scriptcatalog.Lookup(req.ScriptID); ok {
		write = entry.Mode == "write"
	}
	if req.ID != "" {
		v, err := s.operator.Schedule(req.ID)
		if err != nil {
			var auditErr error
			if strings.HasSuffix(r.URL.Path, "/run-now") {
				auditErr = s.operator.RejectScheduleRunNow(req.ID, r.PostForm.Get("idempotency_key"), actor)
			} else {
				auditErr = s.operator.RejectScheduleTransport(actor, scheduleAuditAction(r))
			}
			if auditErr != nil {
				s.fail(w, "Audit", auditErr)
			} else {
				s.scheduleError(w, r, err)
			}
			return actor, false
		}
		if entry, ok := scriptcatalog.Lookup(v.ScriptID); ok && entry.Mode == "write" {
			write = true
		}
	}
	if write {
		if !p.Has(operatorauth.Admin) {
			if err := s.operator.RejectScheduleTransport(actor, scheduleAuditAction(r)); err != nil {
				s.fail(w, "Audit", err)
				return actor, false
			}
			s.renderActionStatus(w, r, 403, "Schedules", "Admin access required", "Write scripts 需要 Admin。", schedulesBack)
			return actor, false
		}
		actor.AuthCapability = p.GrantedCapabilities.Admin
	}
	if apply && p.Has(operatorauth.Admin) {
		if !s.scheduleReauthenticate(w, r) {
			return actor, false
		}
	}
	return actor, true
}
func (s *Server) schedulePreview(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, true) {
		return
	}
	if !operatorWebForm(w, r, map[string]bool{"targets": true}, "id", "name", "script_id", "args", "targets", "cron", "tz", "enabled", "expected_revision", "reason", "operation") {
		s.scheduleBad(w, r)
		return
	}
	req := store.ScheduleRequest{ID: r.PostForm.Get("id"), Name: r.PostForm.Get("name"), ScriptID: r.PostForm.Get("script_id"), Args: json.RawMessage(r.PostForm.Get("args")), Cron: r.PostForm.Get("cron"), TZ: r.PostForm.Get("tz"), Enabled: r.PostForm.Get("enabled") == "true", Reason: r.PostForm.Get("reason")}
	rev, err := strconv.ParseInt(r.PostForm.Get("expected_revision"), 10, 64)
	if err != nil || rev < 0 {
		s.scheduleBad(w, r)
		return
	}
	req.ExpectedRevision = rev
	op := r.PostForm.Get("operation")
	if op == "" {
		op = "upsert"
	}
	if op == "upsert" {
		if (req.ScriptID == "fleet-probe-v1" || req.ScriptID == "fleet-probe-v2") && len(bytes.TrimSpace(req.Args)) == 0 {
			req.Args = json.RawMessage(`{}`)
		}
		if entry, ok := scriptcatalog.Lookup(req.ScriptID); ok {
			req.ScriptSHA256 = entry.SHA256
		}
		req.Targets = r.PostForm["targets"]
	} else {
		req.Args = nil
	}
	actor, ok := s.scheduleActor(w, r, req, false)
	if !ok {
		return
	}
	out, err := s.operator.ScheduleManage(req, op, false, "", actor)
	if err != nil {
		if op == "upsert" {
			v, e := s.scheduleEditView(req)
			if e == nil {
				status, _, detail := operator.HTTPError(err)
				w.WriteHeader(status)
				v.Error = detail
				s.scheduleRender(w, r, "schedule_form.html", v)
				return
			}
		}
		s.scheduleError(w, r, err)
		return
	}
	key, err := operator.NewIdempotencyKey("web-schedule")
	if err != nil {
		s.fail(w, "Request key", err)
		return
	}
	raw, _ := json.Marshal(req)
	canonical, _ := json.MarshalIndent(out.Schedule, "", "  ")
	v := &schedulePage{Confirm: true, Body: string(raw), Canonical: string(canonical), Operation: op, Digest: out.PreviewDigest, Key: key, Edit: req}
	cron, _ := schedulecron.Parse(out.Schedule.Cron)
	loc, _ := time.LoadLocation(out.Schedule.TZ)
	next := time.Now().UTC()
	for i := 0; i < 3; i++ {
		next = cron.NextIn(next, loc)
		v.Times = append(v.Times, next.In(loc).Format("2006-01-02 15:04 MST")+" · "+next.Format(time.RFC3339))
	}
	s.scheduleRender(w, r, "schedule_preview.html", v)
}
func (s *Server) scheduleApply(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, true) {
		return
	}
	if !diskOpsForm(w, r, "request", "operation", "preview_digest", "idempotency_key", "expected_revision", "confirm", "password", "code") || r.PostForm.Get("confirm") != "yes" {
		s.scheduleBad(w, r)
		return
	}
	var req store.ScheduleRequest
	if scheduleDecode(r.PostForm.Get("request"), &req) != nil || strconv.FormatInt(req.ExpectedRevision, 10) != r.PostForm.Get("expected_revision") {
		s.scheduleBad(w, r)
		return
	}
	req.PreviewDigest = r.PostForm.Get("preview_digest")
	actor, ok := s.scheduleActor(w, r, req, true)
	if !ok {
		return
	}
	out, err := s.operator.ScheduleManage(req, r.PostForm.Get("operation"), true, r.PostForm.Get("idempotency_key"), actor)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	if out.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	http.Redirect(w, r, schedulesBack+"/"+out.Schedule.ID, 303)
}
func (s *Server) scheduleDetail(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, false) {
		return
	}
	item, err := s.operator.Schedule(r.PathValue("id"))
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	names, err := s.scheduleNames()
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	row, err := s.scheduleRow(item, names)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	v := &schedulePage{Selected: &row}
	ids, err := s.operator.ScheduleJobIDs(item.ID)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	for _, id := range ids {
		detail, err := s.operator.JobDetail(id, time.Now().UTC())
		if err != nil {
			s.scheduleError(w, r, err)
			return
		}
		job := scheduleJob{JobSummary: detail.Item, Exit: "—", Duration: "—"}
		for _, result := range detail.Verifications.Items {
			if result.ExitCode != nil {
				job.Exit = strconv.Itoa(*result.ExitCode)
			}
		}
		if detail.Item.TerminalAt != nil {
			job.Duration = detail.Item.TerminalAt.Sub(detail.Item.CreatedAt).Round(time.Second).String()
		}
		evidence, err := s.operator.JobEvidence(operator.JobEvidenceRequest{JobID: id}, time.Now().UTC())
		if err != nil {
			s.scheduleError(w, r, err)
			return
		}
		for _, result := range evidence.Verifications.Items {
			if result.RuleID.Text == "script_v1_metadata" && !result.Command.Truncated {
				var metadata scriptcatalog.Result
				if json.Unmarshal([]byte(result.Command.Text), &metadata) == nil && metadata.DurationMS >= 0 {
					job.Exit = strconv.Itoa(metadata.ExitCode)
					job.Duration = (time.Duration(metadata.DurationMS) * time.Millisecond).String()
				}
			}
		}
		v.Jobs = append(v.Jobs, job)
	}
	s.scheduleRender(w, r, "schedule_detail.html", v)
}
func (s *Server) scheduleRunNow(w http.ResponseWriter, r *http.Request) {
	if !s.scheduleAllowed(w, r, true) {
		return
	}
	if !diskOpsForm(w, r, "confirm", "idempotency_key", "password", "code") {
		s.scheduleBad(w, r)
		return
	}
	id := r.PathValue("id")
	actor, ok := s.scheduleActor(w, r, store.ScheduleRequest{ID: id}, r.PostForm.Get("confirm") == "yes")
	if !ok {
		return
	}
	if r.PostForm.Get("confirm") != "yes" {
		v, err := s.operator.Schedule(id)
		if err != nil {
			s.scheduleError(w, r, err)
			return
		}
		key, err := operator.NewIdempotencyKey("web-schedule-now")
		if err != nil {
			s.fail(w, "Request key", err)
			return
		}
		s.scheduleRender(w, r, "schedule_preview.html", &schedulePage{Confirm: true, RunNow: true, Edit: store.ScheduleRequest{ID: id, Name: v.Name}, Key: key})
		return
	}
	out, err := s.operator.ScheduleRunNow(id, r.PostForm.Get("idempotency_key"), actor)
	if err != nil {
		s.scheduleError(w, r, err)
		return
	}
	if out.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	http.Redirect(w, r, schedulesBack+"/"+id, 303)
}

// SetScheduleAdmission installs the same principal rate limiter used by JSON.
func (s *Server) SetScheduleAdmission(admit func(http.ResponseWriter, *http.Request) bool) {
	s.scheduleAdmission = admit
}

func (s *Server) scheduleMachines() (operator.MachineListResult, error) {
	request := operator.MachineListRequest{Limit: operator.MaxMachineReadLimit}
	all := operator.MachineListResult{}
	now := time.Now().UTC()
	for {
		result, err := s.operator.ListMachinesPage(request, now)
		if err != nil {
			return all, err
		}
		all.Items = append(all.Items, result.Items...)
		if result.NextCursor == nil {
			return all, nil
		}
		request.Cursor = *result.NextCursor
	}
}

func (s *Server) scheduleReauthenticate(w http.ResponseWriter, r *http.Request) bool {
	if p, ok := operatorauth.PrincipalFromContext(r.Context()); ok && p.ActionMFAAuthorized {
		return true
	}
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	p, _ := operatorauth.PrincipalFromContext(r.Context())
	actor.AuthCapability = p.GrantedCapabilities.Admin
	err := s.operator.ReauthenticateDiskAdmin(actor, r.PostForm.Get("password"), r.PostForm.Get("code"), !accessFromRequest(r).MFAEnforcementDisabled)
	r.PostForm.Del("password")
	r.PostForm.Del("code")
	r.Form.Del("password")
	r.Form.Del("code")
	if err != nil {
		action := store.AuditAction("schedule-upsert-apply")
		if r.PostForm.Get("operation") == "set-enabled" {
			action = "schedule-set-enabled-apply"
		}
		if strings.HasSuffix(r.URL.Path, "/run-now") {
			action = store.AuditScheduleRunNow
		}
		if auditErr := s.operator.RejectScheduleTransport(actor, action); auditErr != nil {
			s.fail(w, "Audit", auditErr)
		} else {
			s.scheduleError(w, r, err)
		}
		return false
	}
	return true
}

func scheduleAuditAction(r *http.Request) store.AuditAction {
	if strings.HasSuffix(r.URL.Path, "/run-now") {
		return store.AuditScheduleRunNow
	}
	op := r.PostForm.Get("operation")
	if op != "set-enabled" {
		op = "upsert"
	}
	phase := "preview"
	if strings.HasSuffix(r.URL.Path, "/apply") {
		phase = "apply"
	}
	return store.AuditAction("schedule-" + op + "-" + phase)
}
