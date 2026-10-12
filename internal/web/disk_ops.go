package web

import (
	"encoding/json"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

const diskPoliciesBack = "/tenant/disk-policies"
const diskApprovalsBack = "/tenant/approvals"

type diskPoliciesPage struct {
	Items            []store.OpsPolicy
	Selected         *store.OpsPolicy
	Canonical        string
	Edit             store.DiskPolicy
	ID               string
	ExpectedRevision int64
	ProtectPaths     string
	WritesEnabled    bool
}
type diskPolicyReviewPage struct {
	Preview                      store.DiskPolicyResult
	Changes                      []operator.DiskPolicyChange
	Body, Reason, IdempotencyKey string
	WritesEnabled                bool
}
type diskApprovalsPage struct {
	Items                     []store.OpsApproval
	State, Machine, Operation string
	WritesEnabled             bool
}
type diskApprovalReviewPage struct {
	Preview        store.OpsApprovalDecisionResult
	IdempotencyKey string
	WritesEnabled  bool
}

func (s *Server) diskOpsRoutes(mux *http.ServeMux) []string {
	routes := []struct {
		pattern string
		handler http.HandlerFunc
	}{
		{"GET /disk-reports/{id}", s.diskReport},
		{"POST /disk-reports/{id}/actions", s.diskReportAction},
		{"POST /disk-actions/apply", s.diskActionApply},
		{"GET /machines/{id}/quarantine", s.diskQuarantine},
		{"POST /machines/{id}/quarantine/restore", s.diskRestoreAction},
		{"GET /machines/{id}/disk", s.diskMachine}, {"POST /machines/{id}/disk/actions", s.diskMachineAction},
		{"GET /tenant/disk-policies", s.diskPolicies}, {"GET /tenant/disk-policies/{id}", s.diskPolicies},
		{"POST /tenant/disk-policies/preview", s.previewDiskPolicy}, {"POST /tenant/disk-policies/apply", s.applyDiskPolicy},
		{"GET /tenant/approvals", s.diskApprovals}, {"POST /tenant/approvals/preview", s.previewDiskApproval}, {"POST /tenant/approvals/apply", s.applyDiskApproval},
	}
	out := []string{}
	for _, r := range routes {
		mux.HandleFunc(r.pattern, r.handler)
		out = append(out, r.pattern)
	}
	return out
}
func (s *Server) diskOpsError(w http.ResponseWriter, r *http.Request, err error, back string) {
	status, _, detail := operator.HTTPError(err)
	s.renderActionStatus(w, r, status, "Disk operations", "Unable to complete disk operation", detail, back)
}
func (s *Server) diskFormError(w http.ResponseWriter, r *http.Request, back string) {
	if err := s.operator.RecordDiskOpsTransportRejection(operator.ActorFromRequest(r, operator.SourceKindWeb), back, back == diskPoliciesBack); err != nil {
		s.fail(w, "Unable to record request rejection", err)
		return
	}
	s.renderActionStatus(w, r, 400, "Disk operations", "Unable to complete disk operation", "Invalid form. Return to the page and preview again.", back)
}

// The common operator boundary owns CrossOriginProtection. These forms also
// reject duplicate/unknown body fields and queries before reading credentials.
func diskOpsForm(w http.ResponseWriter, r *http.Request, fields ...string) bool {
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return false
	}
	media, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/x-www-form-urlencoded" {
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 65536)
	if err = r.ParseForm(); err != nil {
		return false
	}
	allowed := map[string]bool{}
	for _, f := range fields {
		allowed[f] = true
	}
	for k, v := range r.PostForm {
		if !allowed[k] || (len(v) != 1 && k != "acknowledge_removed_paths" && k != "item_ids") {
			return false
		}
	}
	return true
}
func humanWebAdmin(r *http.Request) bool {
	p, ok := operatorauth.PrincipalFromContext(r.Context())
	return ok && p.Has(operatorauth.Admin) && (p.AuthMethod == operatorauth.AuthMethodLocalAPI || p.AuthMethod == operatorauth.AuthMethodLocalAccountSession)
}
func (s *Server) diskPolicies(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !humanWebAdmin(r) {
		s.renderActionStatus(w, r, 403, "Disk policies", "Admin access required", "Use a human administrator session.", diskPoliciesBack)
		return
	}
	for k, v := range r.URL.Query() {
		if (k != "revision" && k != "section") || len(v) != 1 {
			s.diskFormError(w, r, diskPoliciesBack)
			return
		}
	}
	items, err := s.operator.DiskPolicies()
	if err != nil {
		s.diskOpsError(w, r, err, diskPoliciesBack)
		return
	}
	view := &diskPoliciesPage{Items: items, Edit: store.DefaultDiskPolicy(), ID: "disk-default", WritesEnabled: s.operator.DiskOpsWritesEnabled()}
	if id := r.PathValue("id"); id != "" {
		var p store.OpsPolicy
		if revision := r.URL.Query().Get("revision"); revision != "" {
			n, e := strconv.ParseInt(revision, 10, 64)
			if e != nil || n < 1 {
				s.diskFormError(w, r, diskPoliciesBack)
				return
			}
			p, err = s.operator.DiskPolicyRevision(id, n)
		} else {
			p, err = s.operator.DiskPolicy(id)
		}
		if err != nil {
			s.diskOpsError(w, r, err, diskPoliciesBack)
			return
		}
		view.Selected = &p
		view.Canonical = string(p.Body)
		view.ID = p.ID
		view.ExpectedRevision = p.Revision
		if err = json.Unmarshal(p.Body, &view.Edit); err != nil {
			s.fail(w, "Unable to read policy", err)
			return
		}
		view.ProtectPaths = strings.Join(view.Edit.ProtectPaths, "\n")
	}
	s.render(w, r, "disk_policies.html", page{Title: "Disk policies", Nav: "tenant-disk-policies", DiskPolicies: view})
}

var diskPolicyEditFields = []string{"id", "expected_revision", "user_tmp_min_days", "var_tmp_min_days", "docker_min_hours", "journald_max_mib", "cargo_min_days", "warn_percent", "critical_percent", "deep_report_above_percent", "max_items", "max_entries", "max_seconds", "protect_paths", "reason"}

func diskPolicyFromForm(r *http.Request) (store.DiskPolicyRequest, error) {
	p := store.DefaultDiskPolicy()
	values := []*int{&p.SafeTier.UserTmpMinDays, &p.SafeTier.VarTmpMinDays, &p.SafeTier.DockerMinHours, &p.SafeTier.JournaldMaxMiB, &p.SafeTier.CargoMinDays, &p.Thresholds.WarnPercent, &p.Thresholds.CriticalPercent, &p.Thresholds.DeepReportAbovePercent, &p.ScanBudgets.MaxItems, &p.ScanBudgets.MaxEntries, &p.ScanBudgets.MaxSeconds}
	for i, key := range diskPolicyEditFields[2:13] {
		v, err := strconv.Atoi(r.PostForm.Get(key))
		if err != nil {
			return store.DiskPolicyRequest{}, err
		}
		*values[i] = v
	}
	if raw := strings.TrimSpace(r.PostForm.Get("protect_paths")); raw != "" {
		for _, line := range strings.Split(raw, "\n") {
			p.ProtectPaths = append(p.ProtectPaths, strings.TrimSpace(line))
		}
	}
	rev, err := strconv.ParseInt(r.PostForm.Get("expected_revision"), 10, 64)
	if err != nil {
		return store.DiskPolicyRequest{}, err
	}
	raw, err := json.Marshal(p)
	return store.DiskPolicyRequest{ID: r.PostForm.Get("id"), ExpectedRevision: &rev, Body: raw, Reason: r.PostForm.Get("reason")}, err
}
func (s *Server) previewDiskPolicy(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, diskPolicyEditFields...) {
		s.diskFormError(w, r, diskPoliciesBack)
		return
	}
	req, err := diskPolicyFromForm(r)
	if err != nil {
		s.diskFormError(w, r, diskPoliciesBack)
		return
	}
	preview, err := s.operator.DiskPolicyUpsert(req, false, "", operator.ActorFromRequest(r, operator.SourceKindWeb))
	if err != nil {
		s.diskOpsError(w, r, err, diskPoliciesBack)
		return
	}
	key, err := operator.NewIdempotencyKey("web-disk-policy")
	if err != nil {
		s.fail(w, "Unable to create request key", err)
		return
	}
	s.render(w, r, "disk_policy_review.html", page{Title: "Review disk policy", Nav: "tenant-disk-policies", DiskPolicyReview: &diskPolicyReviewPage{Preview: preview, Changes: operator.DiskPolicyChanges(preview.PreviousBody, preview.Policy.Body), Body: string(preview.Policy.Body), Reason: req.Reason, IdempotencyKey: key, WritesEnabled: s.operator.DiskOpsWritesEnabled()}})
}
func (s *Server) reauthenticateDiskApply(w http.ResponseWriter, r *http.Request, back string) bool {
	err := s.operator.ReauthenticateDiskAdmin(operator.ActorFromRequest(r, operator.SourceKindWeb), r.PostForm.Get("password"), r.PostForm.Get("code"), !accessFromRequest(r).MFAEnforcementDisabled)
	// Never return credentials in an error or preserve them in another form.
	r.PostForm.Del("password")
	r.PostForm.Del("code")
	r.Form.Del("password")
	r.Form.Del("code")
	if err != nil {
		if ae := s.operator.RecordDiskOpsTransportRejection(operator.ActorFromRequest(r, operator.SourceKindWeb), back, back == diskPoliciesBack); ae != nil {
			s.fail(w, "Unable to record rejection", ae)
		} else {
			s.diskOpsError(w, r, err, back)
		}
		return false
	}
	return true
}
func (s *Server) applyDiskPolicy(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, "id", "body", "expected_revision", "expires_at", "preview_digest", "reason", "idempotency_key", "confirm_id", "password", "code", "acknowledge_removed_paths") {
		s.diskFormError(w, r, diskPoliciesBack)
		return
	}
	rev, err := strconv.ParseInt(r.PostForm.Get("expected_revision"), 10, 64)
	expires, e := time.Parse(time.RFC3339, r.PostForm.Get("expires_at"))
	if err != nil || e != nil || r.PostForm.Get("confirm_id") != r.PostForm.Get("id") {
		s.diskFormError(w, r, diskPoliciesBack)
		return
	}
	if !s.reauthenticateDiskApply(w, r, diskPoliciesBack) {
		return
	}
	req := store.DiskPolicyRequest{ID: r.PostForm.Get("id"), Body: json.RawMessage(r.PostForm.Get("body")), ExpectedRevision: &rev, ExpiresAt: expires, PreviewDigest: r.PostForm.Get("preview_digest"), Reason: r.PostForm.Get("reason"), AcknowledgeRemovedPaths: r.PostForm["acknowledge_removed_paths"]}
	out, err := s.operator.DiskPolicyUpsert(req, true, r.PostForm.Get("idempotency_key"), operator.ActorFromRequest(r, operator.SourceKindWeb))
	if err != nil {
		s.diskOpsError(w, r, err, diskPoliciesBack)
		return
	}
	if out.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	http.Redirect(w, r, diskPoliciesBack, 303)
}
func (s *Server) diskApprovals(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	for k, v := range r.URL.Query() {
		if (k != "state" && k != "machine_id" && k != "operation" && k != "section") || len(v) != 1 {
			s.diskFormError(w, r, diskApprovalsBack)
			return
		}
	}
	q := r.URL.Query()
	items, err := s.operator.DiskOpsApprovalsFiltered(q.Get("state"), q.Get("machine_id"), q.Get("operation"), time.Now().UTC())
	if err != nil {
		s.diskOpsError(w, r, err, diskApprovalsBack)
		return
	}
	s.render(w, r, "disk_approvals.html", page{Title: "Approvals", Nav: "tenant-approvals", DiskApprovals: &diskApprovalsPage{Items: items, State: q.Get("state"), Machine: q.Get("machine_id"), Operation: q.Get("operation"), WritesEnabled: s.operator.DiskOpsWritesEnabled()}})
}
func (s *Server) previewDiskApproval(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, "id", "decision", "reason") {
		s.diskFormError(w, r, diskApprovalsBack)
		return
	}
	req := store.OpsApprovalDecisionRequest{ID: r.PostForm.Get("id"), Decision: r.PostForm.Get("decision"), Reason: r.PostForm.Get("reason")}
	out, err := s.operator.DiskOpsApprovalDecision(req, false, "", operator.ActorFromRequest(r, operator.SourceKindWeb))
	if err != nil {
		s.diskOpsError(w, r, err, diskApprovalsBack)
		return
	}
	key, err := operator.NewIdempotencyKey("web-disk-decision")
	if err != nil {
		s.fail(w, "Unable to create request key", err)
		return
	}
	s.render(w, r, "disk_approval_review.html", page{Title: "Review approval decision", Nav: "tenant-approvals", DiskApprovalReview: &diskApprovalReviewPage{Preview: out, IdempotencyKey: key, WritesEnabled: s.operator.DiskOpsWritesEnabled()}})
}
func (s *Server) applyDiskApproval(w http.ResponseWriter, r *http.Request) {
	if !diskOpsForm(w, r, "id", "decision", "policy_revision", "policy_digest", "item_digest", "deadline", "reason", "preview_digest", "idempotency_key", "confirm_id", "password", "code") {
		s.diskFormError(w, r, diskApprovalsBack)
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("policy_revision"), 10, 64)
	deadline, e := time.Parse(time.RFC3339, r.PostForm.Get("deadline"))
	if err != nil || e != nil || r.PostForm.Get("confirm_id") != r.PostForm.Get("id") {
		s.diskFormError(w, r, diskApprovalsBack)
		return
	}
	if !s.reauthenticateDiskApply(w, r, diskApprovalsBack) {
		return
	}
	req := store.OpsApprovalDecisionRequest{ID: r.PostForm.Get("id"), Decision: r.PostForm.Get("decision"), PolicyRevision: revision, PolicyDigest: r.PostForm.Get("policy_digest"), ItemDigest: r.PostForm.Get("item_digest"), Deadline: deadline, Reason: r.PostForm.Get("reason"), PreviewDigest: r.PostForm.Get("preview_digest")}
	out, err := s.operator.DiskOpsApprovalDecision(req, true, r.PostForm.Get("idempotency_key"), operator.ActorFromRequest(r, operator.SourceKindWeb))
	if err != nil {
		s.diskOpsError(w, r, err, diskApprovalsBack)
		return
	}
	if out.Replayed {
		w.Header().Set("Idempotency-Replayed", "true")
	}
	http.Redirect(w, r, diskApprovalsBack, 303)
}

// fmtDiskTime uses the same seconds-level binding as the canonical service.
func fmtDiskTime(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// fmtDiskExpiry presents the remaining TTL alongside the separately rendered
// absolute UTC deadline. It does not promise that safety-deferred expiry ran.
func fmtDiskExpiry(seconds int64) string {
	if seconds <= 0 {
		return "Expiry due"
	}
	if days := seconds / 86400; days > 0 {
		if days == 1 {
			return "1 day left"
		}
		return strconv.FormatInt(days, 10) + " days left"
	}
	if seconds >= 3600 {
		hours := seconds / 3600
		if seconds%3600 != 0 {
			hours++
		}
		return "in " + strconv.FormatInt(hours, 10) + " h"
	}
	if seconds >= 60 {
		minutes := seconds / 60
		if seconds%60 != 0 {
			minutes++
		}
		return "in " + strconv.FormatInt(minutes, 10) + " min"
	}
	return "Less than a minute left"
}
