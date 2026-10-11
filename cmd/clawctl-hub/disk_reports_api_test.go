package main

import (
	"bytes"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/diskreport"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"github.com/teddashh/AI-Intune/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDiskReportMachineHTTPAuthLimitsAndSafeViews(t *testing.T) {
	f := newJobsFixture(t, "example-device")
	h := &hub{store: f.store}
	h.operatorRoutes(f.mux)
	policy := mustDiskOpsJSON(t, store.DefaultDiskPolicy())
	digest := diskreport.Digest(policy)
	entry, _ := scriptcatalog.Lookup("disk-deep-report-v1")
	args := mustDiskOpsJSON(t, map[string]any{"policy_id": "disk-default", "policy_digest": digest, "max_items": 500})
	spec := mustDiskOpsJSON(t, scriptcatalog.Spec{Kind: scriptcatalog.Kind, ScriptID: entry.ID, ScriptSHA256: entry.SHA256, ExecutionMode: "read", Policy: policy, Args: args})
	job := "deep-job-fixture"
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, e := f.store.DB().Exec(`INSERT INTO desired_state VALUES ('desired-report-fixture','machine',?,'script_v1','disk-deep-report-v1',1,?,?, 'fixture')`, f.machine.id, string(spec), now)
	if e != nil {
		t.Fatal(e)
	}
	_, e = f.store.DB().Exec(`INSERT INTO jobs(job_id,machine_id,desired_id,revision,state,lease_token,lease_expires_at,execution_timeout,created_at) VALUES (?,?,'desired-report-fixture',1,'running','fixture-lease',?,600,?)`, job, f.machine.id, time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano), now)
	if e != nil {
		t.Fatal(e)
	}
	report := diskreport.Report{Schema: "disk-deep/v1", PolicyID: "disk-default", PolicyDigest: digest, Items: []diskreport.Item{{ID: "candidate", Category: "app-update-backups", PrivatePath: "/home/private-account/project/old.bak", EvidenceStrength: "weak", Confidence: "low", SuggestedAction: "investigate"}}}
	raw := mustDiskOpsJSON(t, report)
	chunk := diskreport.Chunk{Sequence: 0, Digest: diskreport.Digest(raw), Data: raw}
	post := func(token, path string, body any) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, bytes.NewReader(mustDiskOpsJSON(t, body)))
		r.Header.Set("Content-Type", "application/json")
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		return w
	}
	path := "/v1/disk-reports/" + job
	for _, token := range []string{"", "invalid"} {
		if w := post(token, path+"/chunks", chunk); w.Code != 401 {
			t.Fatal("auth bypass", w.Code)
		}
	}
	other := enrollViaHTTP(t, f.mux, f.store, "another-device")
	if w := post(other.token, path+"/chunks", chunk); w.Code != 403 {
		t.Fatal("job binding bypass", w.Code, w.Body.String())
	}
	oversized := diskreport.Chunk{Data: make([]byte, 65537)}
	oversized.Digest = diskreport.Digest(oversized.Data)
	if w := post(f.machine.token, path+"/chunks", oversized); w.Code != 400 {
		t.Fatal("chunk size", w.Code)
	}
	for n := 0; n < 2; n++ {
		if w := post(f.machine.token, path+"/chunks", chunk); w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	complete := diskreport.Complete{Digest: diskreport.Digest(raw), ItemCount: 1}
	var receipt diskreport.Receipt
	for n := 0; n < 2; n++ {
		w := post(f.machine.token, path+"/complete", complete)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		_ = json.Unmarshal(w.Body.Bytes(), &receipt)
	}
	for _, url := range []string{"/v1/operator/disk-ops/reports", "/v1/operator/disk-ops/reports/" + receipt.ID + "?limit=1"} {
		r := verifiedOperatorRequest(httptest.NewRequest("GET", url, nil), operatorauth.View)
		w := httptest.NewRecorder()
		f.mux.ServeHTTP(w, r)
		if w.Code != 200 || strings.Contains(w.Body.String(), "private-account") || strings.Contains(w.Body.String(), "private_path") || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("unsafe projection", w.Code, w.Body.String())
		}
	}
	for _, pattern := range []string{"GET /v1/operator/disk-ops/reports", "GET /v1/operator/disk-ops/reports/{id}"} {
		p := operatorRoutePolicies[pattern]
		if p.Permission != operatorauth.View || p.ServiceTokenEligible != serviceEligible {
			t.Fatal("read policy")
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/v1/operator/disk-ops/reports/"+receipt.ID+"?limit=101", nil)
	r = verifiedOperatorRequest(r, operatorauth.View)
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != 400 {
		t.Fatal("limit gate", w.Code)
	}
}
