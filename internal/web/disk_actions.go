package web

import (
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"strings"
)

type diskActionView struct {
	Preview       store.DiskActionPreview
	Manifest      store.DiskManifest
	RequestJSON   string
	Key           string
	WritesEnabled bool
}
type diskQuarantineView struct {
	Machine string
	Items   []store.DiskQuarantineItem
	Admin   bool
}

func (s *Server) diskReportAction(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, "report_digest", "item_ids", "reviewed_ids", "single_item", "select_all", "action", "reason", "password", "code") {
		s.diskFormError(w, r, "/")
		return
	}
	if !s.reauthenticateDiskApply(w, r, "/disk-reports/"+r.PathValue("id")) {
		return
	}
	ids := r.PostForm["item_ids"]
	if single := r.PostForm.Get("single_item"); single != "" {
		ids = []string{single}
	}
	if r.PostForm.Get("select_all") == "true" {
		ids = strings.Split(r.PostForm.Get("reviewed_ids"), ",")
	}
	action := r.PostForm.Get("action")
	if action == "" {
		action = "quarantine"
	}
	if single := r.PostForm.Get("single_item"); strings.HasPrefix(single, "reject:") {
		action = "reject"
		ids = []string{strings.TrimPrefix(single, "reject:")}
	}
	req := store.DiskActionRequest{ReportID: r.PathValue("id"), ReportDigest: r.PostForm.Get("report_digest"), ItemIDs: ids, Action: action, Reason: r.PostForm.Get("reason")}
	preview, err := s.operator.DiskActionPreview(req, operator.ActorFromRequest(r, operator.SourceKindWeb))
	if err != nil {
		s.diskOpsError(w, r, err, "/disk-reports/"+req.ReportID)
		return
	}
	s.diskActionConfirmation(w, r, preview)
}
func (s *Server) diskActionConfirmation(w http.ResponseWriter, r *http.Request, preview store.DiskActionPreview) {
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	manifest, err := s.operator.DiskManifestHuman(preview.ManifestID, actor)
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	decision := "approved"
	if manifest.Action == "reject" {
		decision = "rejected"
	}
	plan, err := s.operator.DiskActionDecide(store.OpsApprovalDecisionRequest{ID: preview.Approval.ID, Decision: decision, Reason: manifest.Reason}, false, "", actor)
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	raw, _ := json.Marshal(plan.Request)
	key, err := operator.NewIdempotencyKey("disk-action")
	if err != nil {
		s.fail(w, "Unable to create request key", err)
		return
	}
	s.render(w, r, "disk_action.html", page{Title: "Confirm disk action", DiskAction: &diskActionView{Preview: preview, Manifest: manifest, RequestJSON: string(raw), Key: key, WritesEnabled: s.operator.DiskOpsWritesEnabled()}})
}
func (s *Server) diskActionApply(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, "request", "manifest_id", "idempotency_key", "confirm_action", "password", "code") {
		s.diskFormError(w, r, "/")
		return
	}
	if !s.reauthenticateDiskApply(w, r, "/") {
		return
	}
	actor := operator.ActorFromRequest(r, operator.SourceKindWeb)
	m, err := s.operator.DiskManifestHuman(r.PostForm.Get("manifest_id"), actor)
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	var req store.OpsApprovalDecisionRequest
	if json.Unmarshal([]byte(r.PostForm.Get("request")), &req) != nil || req.ID != m.ApprovalID || r.PostForm.Get("confirm_action") != m.Action {
		s.diskFormError(w, r, "/")
		return
	}
	out, err := s.operator.DiskActionDecide(req, true, r.PostForm.Get("idempotency_key"), actor)
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	if out.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	back := "/disk-reports/" + m.ReportID
	if out.Approval.JobID != "" {
		back = "/jobs/" + out.Approval.JobID
	}
	http.Redirect(w, r, back, http.StatusSeeOther)
}
func (s *Server) diskQuarantine(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" {
		s.diskFormError(w, r, "/")
		return
	}
	items, err := s.operator.DiskQuarantineList(r.PathValue("id"))
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	s.render(w, r, "disk_quarantine.html", page{Title: "Quarantine", DiskQuarantine: &diskQuarantineView{Machine: r.PathValue("id"), Items: items, Admin: humanWebAdmin(r)}})
}
func (s *Server) diskRestoreAction(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, "quarantine_id", "item_ids", "reason", "password", "code") {
		s.diskFormError(w, r, "/")
		return
	}
	if !s.reauthenticateDiskApply(w, r, "/machines/"+r.PathValue("id")+"/quarantine") {
		return
	}
	preview, err := s.operator.DiskRestorePreview(store.DiskRestoreRequest{MachineID: r.PathValue("id"), QuarantineID: r.PostForm.Get("quarantine_id"), ItemIDs: r.PostForm["item_ids"], Reason: r.PostForm.Get("reason")}, operator.ActorFromRequest(r, operator.SourceKindWeb))
	if err != nil {
		s.diskOpsError(w, r, err, "/")
		return
	}
	if preview.Approval.MachineID != r.PathValue("id") {
		s.diskFormError(w, r, "/")
		return
	}
	s.diskActionConfirmation(w, r, preview)
}
