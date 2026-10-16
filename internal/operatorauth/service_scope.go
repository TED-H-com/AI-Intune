package operatorauth

import "strings"

const ServiceScopeOperatorAdmin = "operator-admin"

// OperatorAdminRoute is the explicit automation opt-in for routine admin work.
// It does not confer human identity or access to account/security management.
func OperatorAdminRoute(route string) bool {
	switch route {
	case "POST /v1/operator/enrollment-tokens/preview", "POST /v1/operator/enrollment-tokens",
		"GET /v1/operator/schedules", "GET /v1/operator/schedules/{id}",
		"POST /v1/operator/schedules/{operation}/{phase}", "POST /v1/operator/schedules/{id}/run-now",
		"POST /v1/operator/machines/{id}/profile-assignment-preview", "POST /v1/operator/machines/{id}/profile-assignments",
		"POST /v1/operator/deployments/preview", "POST /v1/operator/deployments",
		"POST /v1/operator/deployments/{id}/continuation-preview", "POST /v1/operator/deployments/{id}/continuations",
		"POST /v1/operator/deployments/{id}/retry-preview", "POST /v1/operator/deployments/{id}/retries":
		return true
	}
	return false
}

// DangerousAction centralizes the actions which always remain human-only and
// require a short MFA window for local sessions. Unknown routes never acquire
// service-token eligibility through this classification.
func DangerousAction(route string) string {
	method, path, _ := strings.Cut(route, " ")
	if method == "GET" || method == "HEAD" {
		return ""
	}
	switch {
	case method == "DELETE" && (strings.Contains(path, "/machines/") || strings.Contains(path, "/tenants/")):
		return "deleting a machine or tenant"
	case strings.HasPrefix(path, "/account/users/") || strings.HasPrefix(path, "/v1/operator/users"):
		return "creating or changing users"
	case strings.HasPrefix(path, "/account/service-tokens/") || strings.HasPrefix(path, "/v1/operator/service-tokens/"):
		return "creating, rotating, or revoking service tokens"
	case strings.HasPrefix(path, "/account/security/") || strings.HasPrefix(path, "/v1/operator/settings/auth") || strings.HasPrefix(path, "/v1/operator/settings/mfa"):
		return "changing authentication or MFA settings"
	}
	return ""
}

func ServiceScopeAllows(scope, required, route string) bool {
	if DangerousAction(route) != "" {
		return false
	}
	if OperatorAdminRoute(route) {
		return scope == ServiceScopeOperatorAdmin
	}
	switch required {
	case "view":
		return scope == "view" || scope == "operate" || scope == ServiceScopeOperatorAdmin
	case "operate":
		return scope == "operate" || scope == ServiceScopeOperatorAdmin
	}
	return false
}
