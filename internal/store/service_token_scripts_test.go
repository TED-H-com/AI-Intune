package store

import (
	"errors"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

func TestServiceTokenScriptStoreChecksBeforeReplay(t *testing.T) {
	st, req, actor, _ := scriptFixture(t)
	actor.AuthMethod = operatorauth.AuthMethodServiceToken
	actor.AuthSubject = "service:hermes"
	preview, err := st.ScriptRun(req, false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	if _, err = st.ScriptRun(req, true, "service-key", actor); err != nil {
		t.Fatal(err)
	}
	if out, err := st.ScriptRun(req, true, "service-key", actor); err != nil || !out.Replayed {
		t.Fatalf("replay=%+v %v", out, err)
	}
	for _, id := range []string{"unknown", "bat-sweep-report-v1"} {
		rejected := req
		rejected.ScriptID = id
		for _, apply := range []bool{false, true} {
			_, err := st.ScriptRun(rejected, apply, "service-key", actor)
			var rejection *OperatorRequestError
			if !errors.As(err, &rejection) || rejection.Code != "SERVICE_TOKEN_READ_SCRIPTS_ONLY" {
				t.Fatalf("rejection %s apply=%t: %v", id, apply, err)
			}
		}
	}
	var n int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes' AND outcome!='ok'`).Scan(&n); err != nil || n != 4 {
		t.Fatalf("denial audits=%d err=%v", n, err)
	}
	actor.AuthCapability = "view"
	if _, err := st.ScriptRun(req, true, "service-key", actor); err == nil {
		t.Fatal("view capability replayed apply")
	}
}

// Exercise the same classification guard used on every store call, including
// a catalog entry becoming write-class after a read preview.
func TestServiceTokenScriptClassification(t *testing.T) {
	actor := AuditEntry{AuthMethod: operatorauth.AuthMethodServiceToken, AuthSubject: "service:hermes", AuthCapability: "operate"}
	for _, mode := range []string{"write", "", "future"} {
		for _, capability := range []string{"operate", "admin", "local-admin"} {
			actor.AuthCapability = capability
			err := scriptScope(scriptcatalog.Entry{ID: "bat-sweep-report-v1", Mode: mode}, actor)
			var rejection *OperatorRequestError
			if !errors.As(err, &rejection) || rejection.Code != "SERVICE_TOKEN_READ_SCRIPTS_ONLY" {
				t.Fatalf("mode=%q capability=%q: %v", mode, capability, err)
			}
		}
	}
	actor.AuthCapability = "operate"
	if err := scriptScope(scriptcatalog.Entry{Mode: "read"}, actor); err != nil {
		t.Fatal(err)
	}
}

func TestServiceTokenRealBATCatalogDeniedBeforeHumanDigestApply(t *testing.T) {
	st, req, actor, _ := scriptFixture(t)
	entry, exists := scriptcatalog.Lookup("bat-sweep-report-v1")
	if !exists || entry.Mode != "write" {
		t.Fatal("real BAT catalog entry must be write-class")
	}
	req.ScriptID, req.ScriptSHA256 = entry.ID, entry.SHA256
	req.Args = []byte(`{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `"}`)
	req.TimeoutSeconds = 600
	actor.AuthCapability = "admin"
	preview, err := st.ScriptRun(req, false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	actor.AuthMethod = operatorauth.AuthMethodServiceToken
	actor.AuthSubject = "service:hermes-bat"
	actor.AuthCapability = "operate"
	for _, apply := range []bool{false, true} {
		_, err := st.ScriptRun(req, apply, "bat-token-denied", actor)
		var rejection *OperatorRequestError
		if !errors.As(err, &rejection) || rejection.Code != "SERVICE_TOKEN_READ_SCRIPTS_ONLY" {
			t.Fatalf("apply=%t: %v", apply, err)
		}
	}
	var count int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE auth_subject='service:hermes-bat' AND outcome!='ok'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("denials=%d err=%v", count, err)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("jobs=%d err=%v", count, err)
	}
}
