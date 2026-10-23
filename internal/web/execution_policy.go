package web

import (
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"net/http"
	"strconv"
	"time"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/store"
)

type executionPolicyPage struct {
	MachineID, Mode, Reason, Digest, Key string
	Revision                             int64
	Manage, MonitorOnly, Pending, Review bool
}

func (s *Server) executionPolicyRoutes(mux *http.ServeMux) []string {
	routes := []string{"POST /machines/{id}/execution-policy/preview", "POST /machines/{id}/execution-policy/apply"}
	for _, route := range routes {
		mux.HandleFunc(route, s.executionPolicyChange)
	}
	return routes
}
func (s *Server) executionPolicyChange(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	back := "/machines/" + r.PathValue("id")
	if !humanWebAdmin(r) {
		s.renderActionStatus(w, r, 403, "Machine profile", "Administrator access required", "Use a human administrator session.", back)
		return
	}
	principal, _ := operatorauth.PrincipalFromContext(r.Context())
	if principal.AuthMethod == operatorauth.AuthMethodLocalAccountSession && !principal.ActionMFAAuthorized && !operatorauth.MFAWithin(principal.MFAVerifiedAt, time.Now(), operatorauth.DangerousMFAWindow) {
		s.renderActionStatus(w, r, 403, "Machine profile", "Confirm your identity", "Use fresh MFA before changing a machine profile.", back)
		return
	}
	if !operatorWebForm(w, r, nil, "mode", "reason", "revision", "preview_digest", "idempotency_key", "confirm") {
		s.renderActionStatus(w, r, 400, "Machine profile", "Invalid form", "Return to the machine and preview again.", back)
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil || revision < 1 {
		s.renderActionStatus(w, r, 400, "Machine profile", "Invalid revision", "Return to the machine and preview again.", back)
		return
	}
	apply := r.URL.Path == back+"/execution-policy/apply"
	if apply && r.PostForm.Get("confirm") != "yes" {
		s.renderActionStatus(w, r, 400, "Machine profile", "Confirmation required", "Review and confirm the profile change.", back)
		return
	}
	req := store.ExecutionPolicyRequest{MachineID: r.PathValue("id"), Mode: r.PostForm.Get("mode"), Reason: r.PostForm.Get("reason"), ExpectedRevision: revision, PreviewDigest: r.PostForm.Get("preview_digest"), IdempotencyKey: r.PostForm.Get("idempotency_key")}
	out, err := s.operator.ManageExecutionPolicy(req, operator.ActorFromRequest(r, operator.SourceKindWeb), apply)
	if err != nil {
		status, _, detail := operator.HTTPError(err)
		s.renderActionStatus(w, r, status, "Machine profile", "Unable to change profile", detail, back)
		return
	}
	if apply {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	key, err := operator.NewIdempotencyKey("machine-profile")
	if err != nil {
		s.fail(w, "Prepare profile confirmation", err)
		return
	}
	s.render(w, r, "execution_policy.html", page{Title: "Review machine profile", Nav: "machines-detail", ExecutionPolicy: &executionPolicyPage{MachineID: out.MachineID, Mode: out.Mode, Revision: out.Revision, Reason: req.Reason, Digest: out.PreviewDigest, Key: key, Review: true, MonitorOnly: out.Mode == "monitor_only"}})
}
