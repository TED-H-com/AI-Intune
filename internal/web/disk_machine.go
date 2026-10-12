package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strconv"
	"time"
)

type diskMachinePage struct {
	OwnershipReview *store.DiskOwnershipResult
	Canary          map[string]store.DiskCanary
	Status          store.DiskOpsStatus
	Policies        []store.OpsPolicy
	Schedules       []store.Schedule
	History         []operator.JobSummary
	Review          string
	Request         string
	Digest          string
	Key             string
	ReadOnly        bool
	Reports         []store.DiskReportSummary
	Operation       string
}

func (s *Server) diskMachine(w http.ResponseWriter, r *http.Request) {
	status, err := s.operator.DiskOpsStatus(r.PathValue("id"))
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	policies, err := s.operator.DiskPolicies()
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	all, err := s.operator.DiskSchedules()
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	schedules := []store.Schedule{}
	for _, v := range all {
		if !scriptcatalog.IsDisk(v.ScriptID) {
			continue
		}
		for _, id := range v.Targets {
			if id == status.MachineID {
				schedules = append(schedules, v)
				break
			}
		}
	}
	history, err := s.operator.ListJobs(operator.JobListRequest{MachineID: status.MachineID, ResourceKind: scriptcatalog.Kind, ResourceID: "disk-safe-clean-v2", Limit: 50}, time.Now().UTC())
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	reports, err := s.operator.DiskReports(status.MachineID)
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	canary := map[string]store.DiskCanary{}
	for _, scope := range []string{"user", "root"} {
		v, e := s.operator.DiskCanaryGet(status.MachineID, scope)
		if e != nil {
			s.diskOpsError(w, r, e, "/")
			return
		}
		canary[scope] = v
	}
	s.render(w, r, "disk_machine.html", page{Title: "Disk", DiskMachine: &diskMachinePage{Status: status, Canary: canary, Policies: policies, Schedules: schedules, History: history.Items, Reports: reports}})
}
func (s *Server) diskMachineAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	back := "/machines/" + id + "/disk"
	if !diskOpsForm(w, r, "action", "policy_id", "scope", "reason", "minute", "hour", "schedule_id", "revision", "enabled", "request", "digest", "key", "operation", "password", "code") {
		s.diskFormError(w, r, back)
		return
	}
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	action := r.PostForm.Get("action")
	if action == "apply" {
		if !s.reauthenticateDiskApply(w, r, back) {
			return
		}
		raw := r.PostForm.Get("request")
		switch r.PostForm.Get("operation") {
		case "script":
			var req store.ScriptRunRequest
			if json.Unmarshal([]byte(raw), &req) != nil || len(req.Targets) != 1 || req.Targets[0] != id || !scriptcatalog.IsDisk(req.ScriptID) {
				s.diskFormError(w, r, back)
				return
			}
			req.PreviewDigest = r.PostForm.Get("digest")
			_, err := s.operator.ScriptRun(req, true, r.PostForm.Get("key"), actor)
			if err != nil {
				s.diskOpsError(w, r, err, back)
				return
			}
		case "run-now":
			v, e := s.operator.DiskSchedule(raw)
			if e != nil || !diskScheduleTarget(v, id) {
				s.diskFormError(w, r, back)
				return
			}
			_, e = s.operator.DiskScheduleRunNow(raw, r.PostForm.Get("digest"), r.PostForm.Get("key"), true, actor)
			if e != nil {
				s.diskOpsError(w, r, e, back)
				return
			}
		case "upsert", "set-enabled":
			var req store.ScheduleRequest
			if json.Unmarshal([]byte(raw), &req) != nil {
				s.diskFormError(w, r, back)
				return
			}
			if r.PostForm.Get("operation") == "upsert" {
				if len(req.Targets) != 1 || req.Targets[0] != id || !scriptcatalog.IsDisk(req.ScriptID) {
					s.diskFormError(w, r, back)
					return
				}
			} else {
				v, e := s.operator.DiskSchedule(req.ID)
				if e != nil || !diskScheduleTarget(v, id) {
					s.diskFormError(w, r, back)
					return
				}
			}
			req.PreviewDigest = r.PostForm.Get("digest")
			_, err := s.operator.ScheduleManage(req, r.PostForm.Get("operation"), true, r.PostForm.Get("key"), actor)
			if err != nil {
				s.diskOpsError(w, r, err, back)
				return
			}
		default:
			s.diskFormError(w, r, back)
			return
		}
		http.Redirect(w, r, back, 303)
		return
	}
	if action == "run-now" {
		v, err := s.operator.DiskSchedule(r.PostForm.Get("schedule_id"))
		if err != nil || !diskScheduleTarget(v, id) {
			s.diskFormError(w, r, back)
			return
		}
		out, err := s.operator.DiskScheduleRunNow(v.ID, "", "", false, actor)
		if err != nil {
			s.diskOpsError(w, r, err, back)
			return
		}
		key, err := operator.NewIdempotencyKey("web-disk-now")
		if err != nil {
			s.fail(w, "Request key", err)
			return
		}
		s.render(w, r, "disk_machine.html", page{Title: "Review scheduled cleanup", DiskMachine: &diskMachinePage{Status: store.DiskOpsStatus{MachineID: id, WritesEnabled: s.operator.DiskOpsWritesEnabled()}, ReadOnly: v.ExecutionMode == "read", Review: "Run scheduled disk job now", Operation: "run-now", Request: v.ID, Digest: out.PreviewDigest, Key: key}})
		return
	}

	policy, err := s.operator.DiskPolicy(r.PostForm.Get("policy_id"))
	if err != nil && action != "toggle" {
		s.diskOpsError(w, r, err, back)
		return
	}
	scope := r.PostForm.Get("scope")
	if scope == "" {
		scope = "user"
	}
	args, _ := json.Marshal(map[string]string{"scope": scope, "policy_id": policy.ID, "policy_digest": policy.Digest})
	key, err := operator.NewIdempotencyKey("web-disk")
	if err != nil {
		s.fail(w, "Request key", err)
		return
	}
	view := &diskMachinePage{Status: store.DiskOpsStatus{MachineID: id, WritesEnabled: s.operator.DiskOpsWritesEnabled()}, Key: key}
	if action == "preview" || action == "cleanup" || action == "deep" {
		script := "disk-safe-clean-v2"
		if action == "preview" {
			script = "disk-safe-preview-v2"
		}
		if action == "deep" {
			script = "disk-deep-report-v1"
			args, _ = json.Marshal(map[string]any{"policy_id": policy.ID, "policy_digest": policy.Digest, "max_items": 500})
			view.ReadOnly = true
		}
		entry, _ := scriptcatalog.Lookup(script)
		req := store.ScriptRunRequest{ScriptID: script, ScriptSHA256: entry.SHA256, Args: args, Targets: []string{id}, Reason: r.PostForm.Get("reason")}
		out, e := s.operator.ScriptRun(req, false, "", actor)
		if e != nil {
			s.diskOpsError(w, r, e, back)
			return
		}
		if action == "preview" {
			req.PreviewDigest = out.PreviewDigest
			_, e = s.operator.ScriptRun(req, true, key, actor)
			if e != nil {
				s.diskOpsError(w, r, e, back)
				return
			}
			http.Redirect(w, r, back, 303)
			return
		}
		raw, _ := json.Marshal(req)
		view.Request = string(raw)
		view.Digest = out.PreviewDigest
		view.Operation = "script"
		view.Review = "Run safe cleanup"
		if action == "deep" {
			view.Review = "Run deep analysis (read only)"
		}
	} else if action == "schedule" || action == "toggle" {
		req := store.ScheduleRequest{Reason: r.PostForm.Get("reason")}
		op := "upsert"
		if action == "schedule" {
			minute, e := strconv.Atoi(r.PostForm.Get("minute"))
			hour, h := strconv.Atoi(r.PostForm.Get("hour"))
			if e != nil || h != nil || minute < 0 || minute > 59 || hour < 0 || hour > 23 {
				s.diskFormError(w, r, back)
				return
			}
			if scope == "root" {
				s.renderActionStatus(w, r, 412, "Disk", "Root helper unavailable", "Root schedules require helper-ready targets; this agent adapter has no installed root helper.", back)
				return
			}
			reason := req.Reason
			if scope == "deep" {
				req, err = store.DiskDeepScheduleTemplate(policy.ID, policy.Digest, id, hour, minute)
				view.ReadOnly = true
			} else {
				req, err = store.DiskScheduleTemplate(func() string {
					if scope == "compare" {
						return "user"
					}
					return scope
				}(), policy.ID, policy.Digest, id, hour, minute)
			}
			if err != nil {
				s.diskOpsError(w, r, err, back)
				return
			}
			if scope == "compare" {
				entry, _ := scriptcatalog.Lookup("disk-safe-preview-v2")
				req.Name = "compare-disk-user-" + scriptcatalog.Digest([]byte(id))[:12]
				req.ScriptID = entry.ID
				req.ScriptSHA256 = entry.SHA256
				req.Args, _ = json.Marshal(map[string]string{"scope": "user", "policy_id": policy.ID, "policy_digest": policy.Digest})
				req.Enabled = true
				view.ReadOnly = true
			}
			req.Reason = reason
			if scope != "deep" && scope != "compare" {
				req.Enabled = false
			}
			if scheduleID := r.PostForm.Get("schedule_id"); scheduleID != "" {
				v, e := s.operator.DiskSchedule(scheduleID)
				if e != nil || !diskScheduleTarget(v, id) {
					s.diskFormError(w, r, back)
					return
				}
				revision, e := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
				if e != nil {
					s.diskFormError(w, r, back)
					return
				}
				req.ID = v.ID
				req.Name = v.Name
				req.ExpectedRevision = revision
				req.Enabled = v.Enabled
			}
		} else {
			v, e := s.operator.DiskSchedule(r.PostForm.Get("schedule_id"))
			if e != nil || !diskScheduleTarget(v, id) {
				s.diskFormError(w, r, back)
				return
			}
			req.ID = v.ID
			req.ExpectedRevision = v.Revision
			req.Enabled = !v.Enabled
			op = "set-enabled"
		}
		out, e := s.operator.ScheduleManage(req, op, false, "", actor)
		if e != nil {
			s.diskOpsError(w, r, e, back)
			return
		}
		raw, _ := json.Marshal(req)
		view.Request = string(raw)
		view.Digest = out.PreviewDigest
		view.Operation = op
		view.Review = "Review disk schedule"
		view.ReadOnly = out.Schedule.ExecutionMode == "read"
	} else {
		s.diskFormError(w, r, back)
		return
	}
	s.render(w, r, "disk_machine.html", page{Title: "Review disk operation", DiskMachine: view})
}
func diskScheduleTarget(v store.Schedule, id string) bool {
	return scriptcatalog.IsDisk(v.ScriptID) && len(v.Targets) == 1 && v.Targets[0] == id
}
