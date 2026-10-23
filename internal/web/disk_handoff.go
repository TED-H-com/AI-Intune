package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strconv"
)

type diskAlertsPage struct {
	Next    string
	Labels  map[string][]store.DiskMountUsage
	Items   []store.DiskAlert
	Ack     *store.DiskAlertAckResult
	Request string
	Key     string
}

func (s *Server) diskAlerts(w http.ResponseWriter, r *http.Request) {
	if len(r.URL.Query()) > 1 || (len(r.URL.Query()) == 1 && !r.URL.Query().Has("after")) || len(r.URL.Query()["after"]) > 1 {
		http.Error(w, "Invalid pagination", http.StatusBadRequest)
		return
	}
	data, err := loadDiskAlertsPage(s.operator, r.URL.Query().Get("after"))
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	s.render(w, r, "disk_alerts.html", page{Title: "Disk alerts", Nav: "tenant-disk-alerts", DiskAlerts: data})
}

type diskAlertsPageSource interface {
	DiskAlertsPageAfter(string) (store.DiskAlertsPage, error)
	DiskAlertMountLabels([]string) (map[string][]store.DiskMountUsage, error)
}

func loadDiskAlertsPage(source diskAlertsPageSource, after string) (*diskAlertsPage, error) {
	result, err := source.DiskAlertsPageAfter(after)
	if err != nil {
		return nil, err
	}
	machines := []string{}
	seen := map[string]bool{}
	for _, a := range result.Items {
		if !seen[a.MachineID] {
			seen[a.MachineID] = true
			machines = append(machines, a.MachineID)
		}
	}
	labels, err := source.DiskAlertMountLabels(machines)
	if err != nil {
		return nil, err
	}
	return &diskAlertsPage{Items: result.Items, Labels: labels, Next: result.Next}, nil
}

func (s *Server) diskOwnershipAction(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	back := "/machines/" + id + "/disk"
	if !diskOpsForm(w, r, "action", "scope", "reason", "override", "revision", "request", "digest", "key", "password", "code", "confirm_id") {
		s.diskFormError(w, r, back)
		return
	}
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	if r.PostForm.Get("action") == "apply" {
		if r.PostForm.Get("confirm_id") != id {
			s.diskFormError(w, r, back)
			return
		}
		if !s.reauthenticateDiskApply(w, r, back) {
			return
		}
		var req store.DiskOwnershipRequest
		if json.Unmarshal([]byte(r.PostForm.Get("request")), &req) != nil || req.MachineID != id {
			s.diskFormError(w, r, back)
			return
		}
		req.PreviewDigest = r.PostForm.Get("digest")
		if _, err := s.operator.DiskOwnershipManage(req, true, r.PostForm.Get("key"), actor); err != nil {
			s.diskOpsError(w, r, err, back)
			return
		}
		http.Redirect(w, r, back, 303)
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil {
		s.diskFormError(w, r, back)
		return
	}
	req := store.DiskOwnershipRequest{MachineID: id, Scope: r.PostForm.Get("scope"), Action: r.PostForm.Get("action"), ExpectedRevision: revision, Reason: r.PostForm.Get("reason"), OverrideCanary: r.PostForm.Get("override") == "yes"}
	out, err := s.operator.DiskOwnershipManage(req, false, "", actor)
	if err != nil {
		s.diskOpsError(w, r, err, back)
		return
	}
	req.ExpiresAt = out.ExpiresAt
	raw, _ := json.Marshal(req)
	key, err := operator.NewIdempotencyKey("web-ownership")
	if err != nil {
		s.fail(w, "key", err)
		return
	}
	s.render(w, r, "disk_machine.html", page{Title: "Confirm disk ownership", DiskMachine: &diskMachinePage{Status: store.DiskOpsStatus{MachineID: id}, OwnershipReview: &out, Operation: req.Action, Request: string(raw), Digest: out.PreviewDigest, Key: key}})
}

func (s *Server) diskAlertAck(w http.ResponseWriter, r *http.Request) {
	back := "/tenant/disk-alerts"
	if !diskOpsForm(w, r, "id", "reason", "request", "digest", "key", "password", "code") {
		s.diskFormError(w, r, back)
		return
	}
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	if r.URL.Path == back+"/ack" {
		if !s.reauthenticateDiskApply(w, r, back) {
			return
		}
		var req store.DiskAlertAckRequest
		if json.Unmarshal([]byte(r.PostForm.Get("request")), &req) != nil {
			s.diskFormError(w, r, back)
			return
		}
		req.PreviewDigest = r.PostForm.Get("digest")
		if _, e := s.operator.DiskAlertAcknowledge(req, true, r.PostForm.Get("key"), actor); e != nil {
			s.diskOpsError(w, r, e, back)
			return
		}
		http.Redirect(w, r, back, 303)
		return
	}
	req := store.DiskAlertAckRequest{ID: r.PostForm.Get("id"), Reason: r.PostForm.Get("reason")}
	out, e := s.operator.DiskAlertAcknowledge(req, false, "", actor)
	if e != nil {
		s.diskOpsError(w, r, e, back)
		return
	}
	req.ExpiresAt = out.ExpiresAt
	raw, _ := json.Marshal(req)
	key, e := operator.NewIdempotencyKey("web-alert-ack")
	if e != nil {
		s.fail(w, "key", e)
		return
	}
	s.render(w, r, "disk_alerts.html", page{Title: "Review acknowledgement", Nav: "tenant-disk-alerts", DiskAlerts: &diskAlertsPage{Ack: &out, Request: string(raw), Key: key}})
}
