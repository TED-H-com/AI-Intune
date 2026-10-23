package operatorauth

import "testing"

func TestOperatorAdminDoesNotGrantHumanActions(t *testing.T) {
	for _, route := range []string{"DELETE /v1/operator/machines/{id}", "DELETE /v1/operator/tenants/{id}", "POST /account/users/create", "POST /account/users/rename", "POST /account/security/totp/disable", "POST /account/service-tokens/create", "POST /v1/operator/service-tokens/rotate"} {
		for _, scope := range []string{"view", "operate", ServiceScopeOperatorAdmin} {
			if DangerousAction(route) == "" || ServiceScopeAllows(scope, "admin", route) {
				t.Fatalf("dangerous action delegated: %s", route)
			}
		}
	}
	if OperatorAdminRoute("POST /v1/operator/future-admin") || ServiceScopeAllows(ServiceScopeOperatorAdmin, "admin", "POST /v1/operator/future-admin") {
		t.Fatal("future actions must fail closed")
	}
}

func TestScheduleReadScopes(t *testing.T) {
	for _, scope := range []string{"view", "operate", ServiceScopeOperatorAdmin} {
		for _, route := range []string{"GET /v1/operator/schedules", "GET /v1/operator/schedules/{id}"} {
			if !ServiceScopeAllows(scope, "view", route) {
				t.Fatalf("read denied: %s %s", scope, route)
			}
		}
		for _, route := range []string{"POST /v1/operator/schedules/{operation}/{phase}", "POST /v1/operator/schedules/{id}/run-now"} {
			if ServiceScopeAllows(scope, "operate", route) != (scope == ServiceScopeOperatorAdmin) {
				t.Fatalf("mutation scope: %s %s", scope, route)
			}
		}
	}
}
