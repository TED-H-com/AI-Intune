package operatoragent

// toolRoutes names every Hub operator route pattern a tool calls. A service
// token sees a tool only when its allowlist holds all of them. Tests keep this
// in step with Tools() and with the Hub's registered routes.
var toolRoutes = map[string][]string{
	"signins_list":                   {"GET /v1/operator/signins"},
	"jobs_summary":                   {"GET /v1/operator/jobs-summary"},
	"approvals_summary":              {"GET /v1/operator/approvals-summary"},
	"loops_list":                     {"GET /v1/operator/loops"},
	"hub_status":                     {"GET /v1/operator/hub-status"},
	"fleet_overview":                 {"GET /v1/operator/machines"},
	"machines_list":                  {"GET /v1/operator/machines"},
	"machine_get":                    {"GET /v1/operator/machines/{id}"},
	"machine_disks":                  {"GET /v1/operator/machines/{id}/disks"},
	"host_profile_get":               {"GET /v1/operator/host-profile"},
	"join_requests_list":             {"GET /v1/operator/joins"},
	"machine_readiness":              {"GET /v1/operator/machines/{id}/readiness"},
	"machine_safe_detail":            {"GET /v1/operator/machines/{id}/safe"},
	"machine_oom_kills":              {"GET /v1/operator/machines/{id}/oom-kills"},
	"machine_evidence":               {"GET /v1/operator/machines/{id}/evidence"},
	"jobs_list":                      {"GET /v1/operator/jobs"},
	"job_get":                        {"GET /v1/operator/jobs/{id}"},
	"job_evidence":                   {"GET /v1/operator/jobs/{id}/evidence"},
	"deployments_list":               {"GET /v1/operator/deployments"},
	"deployment_get":                 {"GET /v1/operator/deployments/{id}"},
	"software_report":                {"GET /v1/operator/software-report"},
	"compliance":                     {"GET /v1/operator/compliance"},
	"rollout_status":                 {"GET /v1/operator/deployments/{id}"},
	"rollout_preview":                {"POST /v1/operator/deployments/preview"},
	"rollout_apply":                  {"POST /v1/operator/deployments"},
	"rollout_expand":                 {"GET /v1/operator/deployments/{id}", "POST /v1/operator/deployments/{id}/continuations"},
	"enroll_ticket_preview":          {"POST /v1/operator/enrollment-tokens/preview"},
	"enroll_ticket_create":           {"POST /v1/operator/enrollment-tokens"},
	"deployment_create_preview":      {"POST /v1/operator/deployments/preview"},
	"deployment_create":              {"POST /v1/operator/deployments"},
	"deployment_continue_preview":    {"POST /v1/operator/deployments/{id}/continuation-preview"},
	"deployment_continue":            {"GET /v1/operator/deployments/{id}", "POST /v1/operator/deployments/{id}/continuations"},
	"deployment_abandon_preview":     {"POST /v1/operator/deployments/{id}/abandonment-preview"},
	"deployment_abandon":             {"POST /v1/operator/deployments/{id}/abandonments"},
	"profile_assignment_preview":     {"POST /v1/operator/machines/{id}/profile-assignment-preview"},
	"profile_assignment_apply":       {"POST /v1/operator/machines/{id}/profile-assignments"},
	"disk_clean_summaries":           {"GET /v1/operator/disk-clean/summaries"},
	"disk_clean_summary":             {"GET /v1/operator/disk-clean/summaries/{id}"},
	"disk_clean_profile_preview":     {"POST /v1/operator/disk-clean/profile-preview"},
	"disk_clean_profile_publish":     {"POST /v1/operator/disk-clean/profiles"},
	"disk_clean_dry_run_preview":     {"POST /v1/operator/disk-clean/dry-run-preview"},
	"disk_clean_dry_run_apply":       {"POST /v1/operator/disk-clean/dry-runs"},
	"disk_clean_canary_preview":      {"POST /v1/operator/disk-clean/canary-preview"},
	"disk_clean_canary_apply":        {"POST /v1/operator/disk-clean/canaries"},
	"disk_clean_continue_preview":    {"POST /v1/operator/disk-clean/continuation-preview"},
	"disk_clean_continue_apply":      {"POST /v1/operator/disk-clean/continuations"},
	"disk_clean_abandon_preview":     {"POST /v1/operator/disk-clean/abandonment-preview"},
	"disk_clean_abandon_apply":       {"POST /v1/operator/disk-clean/abandonments"},
	"script_catalog_list":            {"GET /v1/operator/script-catalog"},
	"script_run_preview":             {"POST /v1/operator/script-runs/preview"},
	"script_run_apply":               {"POST /v1/operator/script-runs"},
	"schedule_list":                  {"GET /v1/operator/schedules"},
	"schedule_get":                   {"GET /v1/operator/schedules/{id}"},
	"schedule_run_now":               {"POST /v1/operator/schedules/{id}/run-now"},
	"schedule_job_cancel":            {"POST /v1/operator/schedule-jobs/{id}/cancel"},
	"schedule_upsert_preview":        {"POST /v1/operator/schedules/{operation}/{phase}"},
	"schedule_upsert_apply":          {"POST /v1/operator/schedules/{operation}/{phase}"},
	"schedule_set_enabled_preview":   {"POST /v1/operator/schedules/{operation}/{phase}"},
	"schedule_set_enabled_apply":     {"POST /v1/operator/schedules/{operation}/{phase}"},
	"certificate_list":               {"GET /v1/operator/certificates"},
	"certificate_get":                {"GET /v1/operator/certificates/{id}"},
	"disk_ops_status":                {"GET /v1/operator/disk-ops/status/{machine_id}"},
	"disk_report_get":                {"GET /v1/operator/disk-ops/reports/{id}"},
	"disk_policy_list":               {"GET /v1/operator/disk-ops/policies"},
	"disk_policy_get":                {"GET /v1/operator/disk-ops/policies/{id}"},
	"disk_alerts_list":               {"GET /v1/operator/disk-ops/alerts"},
	"disk_ownership_get":             {"GET /v1/operator/disk-ops/ownership/{machine_id}/{scope}"},
	"disk_policy_upsert_preview":     {"POST /v1/operator/disk-ops/policies/preview"},
	"disk_policy_upsert_apply":       {"POST /v1/operator/disk-ops/policies"},
	"disk_approval_list":             {"GET /v1/operator/disk-ops/approvals"},
	"disk_approval_decision_preview": {"POST /v1/operator/disk-ops/approvals/{id}/decision/preview"},
	"disk_approval_decision_apply":   {"POST /v1/operator/disk-ops/approvals/{id}/decision"},
	"disk_action_preview":            {"POST /v1/operator/disk-ops/actions/preview"},
	"disk_action_decide":             {"POST /v1/operator/disk-ops/actions/decide"},
	"disk_quarantine_list":           {"GET /v1/operator/disk-ops/quarantine/{machine_id}"},
	"disk_restore_preview":           {"POST /v1/operator/disk-ops/restores/preview"},
	"disk_restore_apply":             {"POST /v1/operator/disk-ops/restores"},
}

// ToolRoutes returns the Hub route patterns tool calls, or nil if unknown.
func ToolRoutes(tool string) []string { return toolRoutes[tool] }

// ToolsFor lists the tools a service token with this allowlist can call. A nil
// allowlist (tailnet identity, no token) lists every tool; Hub still decides.
func ToolsFor(allowlist []string) []Tool {
	all := Tools()
	if allowlist == nil {
		return all
	}
	allowed := map[string]bool{}
	for _, route := range allowlist {
		allowed[route] = true
	}
	out := []Tool{}
next:
	for _, tool := range all {
		routes := toolRoutes[tool.Name]
		if len(routes) == 0 {
			continue
		}
		for _, route := range routes {
			if !allowed[route] {
				continue next
			}
		}
		out = append(out, tool)
	}
	return out
}
