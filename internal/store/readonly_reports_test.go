package store

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
)

func TestReadReportVerificationPreservesDigestAndRedactsIdentity(t *testing.T) {
	st, req, actor, now := scriptFixture(t)
	e, _ := scriptcatalog.Lookup("network-watch-v1")
	req.ScriptID, req.ScriptSHA256, req.Args = e.ID, e.SHA256, json.RawMessage(`{}`)
	preview, err := st.ScriptRun(req, false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	run, err := st.ScriptRun(req, true, "network-evidence", actor)
	if err != nil {
		t.Fatal(err)
	}
	job, machine := run.JobIDs[0], req.Targets[0]
	token, err := st.ClaimJob(job, machine, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.AdvanceJobByAgent(job, machine, token, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	stdout := `{"schema_version":1,"status":"warn","summary":"user@example.invalid token=example","metrics":{"listen_digest":"` + digest + `"},"findings":[]}`
	if err := st.RecordVerification(job, machine, token, scriptcatalog.Kind, req.ScriptID, 0, stdout, "token=example", true, now); err != nil {
		t.Fatal(err)
	}
	var storedOut, storedErr string
	if err := st.rdb.QueryRow(`SELECT stdout_excerpt,stderr_excerpt FROM verification_results WHERE job_id=? AND rule_id=?`, job, scriptcatalog.Kind).Scan(&storedOut, &storedErr); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(storedOut, digest) || strings.Contains(storedOut, "user@") || strings.Contains(storedOut+storedErr, "token=example") || !json.Valid([]byte(storedOut)) {
		t.Fatalf("unsafe report evidence: %s %s", storedOut, storedErr)
	}
}
