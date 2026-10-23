package localauth

import (
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/store"
)

func TestAccountPrincipalPreservesSessionFields(t *testing.T) {
	verified := time.Date(2026, time.October, 15, 12, 0, 0, 0, time.UTC)
	account := store.HubAccount{AccountID: "account-1", Username: "operator", Role: "admin", SessionMFAVerifiedAt: verified}
	names := operatorauth.CapabilityNames{View: "test-view", Operate: "test-operate", Admin: "test-admin"}
	want := operatorauth.Principal{
		MFAVerifiedAt: verified,
		NodeStableID:  "local-session", DeviceName: "browser",
		TailnetUserID: "local:account-1", TailnetUserLogin: "operator", TailnetDisplayName: "operator",
		AuthMethod: operatorauth.AuthMethodLocalAccountSession, GrantedCapabilities: names,
	}
	if got := AccountPrincipal(account, names); got != want {
		t.Fatalf("AccountPrincipal() = %+v, want %+v", got, want)
	}
	for _, tc := range []struct {
		name, role string
		disabled   bool
	}{
		{name: "non-admin", role: "viewer"},
		{name: "disabled admin", role: "admin", disabled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account.Role, account.Disabled = tc.role, tc.disabled
			p := AccountPrincipal(account, names)
			for _, permission := range []operatorauth.Permission{operatorauth.View, operatorauth.Operate, operatorauth.Admin} {
				if p.Has(permission) {
					t.Fatalf("unexpected %s permission", permission)
				}
			}
		})
	}
}
