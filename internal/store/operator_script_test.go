package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/deploy"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"strings"
	"testing"
	"time"
)

func scriptFixture(t *testing.T) (*Store, ScriptRunRequest, AuditEntry, time.Time) {
	st := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	id := mustEnroll(t, st, "probe-node", now)
	c := healthyCheckin(now)
	c.ScriptV1 = true
	if err := st.RecordCheckin(id, c, now); err != nil {
		t.Fatal(err)
	}
	e, _ := scriptcatalog.Lookup("fleet-probe-v1")
	return st, ScriptRunRequest{ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: json.RawMessage(`{}`), Targets: []string{id}, Reason: "collect facts"}, AuditEntry{AuthSubject: "operator-test", AuthCapability: "operate"}, now
}
func TestScriptRunRejectsInvalidRequests(t *testing.T) {
	st, req, a, _ := scriptFixture(t)
	for _, tc := range []struct {
		name   string
		change func(*ScriptRunRequest, *AuditEntry)
	}{
		{"unknown", func(r *ScriptRunRequest, a *AuditEntry) { r.ScriptID = "unknown" }},
		{"hash", func(r *ScriptRunRequest, a *AuditEntry) { r.ScriptSHA256 = strings.Repeat("a", 64) }},
		{"targets", func(r *ScriptRunRequest, a *AuditEntry) { r.Targets = make([]string, 51) }},
		{"scope", func(r *ScriptRunRequest, a *AuditEntry) { a.AuthCapability = "view" }},
		{"args", func(r *ScriptRunRequest, a *AuditEntry) { r.Args = json.RawMessage(`{"command":"true"}`) }},
		{"timeout", func(r *ScriptRunRequest, a *AuditEntry) { r.TimeoutSeconds = 61 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, actor := req, a
			tc.change(&r, &actor)
			if _, err := st.ScriptRun(r, true, "reject-"+tc.name, actor); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
	var count int
	if err := st.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 0 {
		t.Fatal("rejection created job")
	}
}
func TestScriptRunPreviewApplyReplayCompletionAudit(t *testing.T) {
	st, req, a, now := scriptFixture(t)
	preview, err := st.ScriptRun(req, false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	result, err := st.ScriptRun(req, true, "script-key", a)
	if err != nil || len(result.JobIDs) != 1 {
		t.Fatalf("apply %+v %v", result, err)
	}
	replay, err := st.ScriptRun(req, true, "script-key", a)
	if err != nil || !replay.Replayed || replay.JobIDs[0] != result.JobIDs[0] {
		t.Fatalf("replay %+v %v", replay, err)
	}
	changed := req
	changed.Reason = "different reason"
	if _, err := st.ScriptRun(changed, true, "script-key", a); err == nil {
		t.Fatal("idempotency conflict accepted")
	}
	id := result.JobIDs[0]
	machine := req.Targets[0]
	token, err := st.ClaimJob(id, machine, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.AdvanceJobByAgent(id, machine, token, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	metadata := scriptcatalog.Result{StdoutSHA256: scriptcatalog.Digest([]byte("private evidence")), StderrSHA256: scriptcatalog.Digest(nil), ExitCode: 0}
	for rule, command := range map[string]string{scriptcatalog.Kind: req.ScriptID, "script_v1_metadata": string(mustScriptJSON(metadata))} {
		if err = st.RecordVerification(id, machine, token, rule, command, 0, "private evidence", "", true, now); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = st.AdvanceJobByAgent(id, machine, token, deploy.FinishWork, now); err != nil {
		t.Fatal(err)
	}
	if state, err := st.MarkSucceededIfVerified(id, now); err != nil || state != deploy.Succeeded {
		t.Fatalf("complete %s %v", state, err)
	}
	rows, err := st.Audit("", 100)
	if err != nil {
		t.Fatal(err)
	}
	complete := 0
	for _, row := range rows {
		if strings.Contains(row.Detail, "private evidence") {
			t.Fatal("raw output leaked into audit")
		}
		if row.Action == AuditScriptComplete {
			complete++
			if row.AuthSubject != a.AuthSubject || !strings.Contains(row.Detail, metadata.StdoutSHA256) {
				t.Fatal("completion provenance missing")
			}
		}
	}
	if complete != 1 {
		t.Fatalf("completion audits %d", complete)
	}
	if _, err = st.MarkSucceededIfVerified(id, now); err != nil {
		t.Fatal(err)
	}
}
func TestScriptRunFanoutRollsBackOnUnavailableTarget(t *testing.T) {
	st, req, a, _ := scriptFixture(t)
	req.Targets = append(req.Targets, "missing-machine")
	if _, err := st.ScriptRun(req, false, "", a); err == nil {
		t.Fatal("missing target accepted")
	}
	var n int
	_ = st.rdb.QueryRow(`SELECT COUNT(*) FROM desired_state`).Scan(&n)
	if n != 0 {
		t.Fatal("partial fanout")
	}
}

func TestScriptScopeTracksCatalogMode(t *testing.T) {
	for _, tc := range []struct {
		mode, scope string
		allowed     bool
	}{{"read", "operate", true}, {"read", "view", false}, {"read", "admin", false}, {"write", "operate", false}, {"write", "admin", true}} {
		err := scriptScope(scriptcatalog.Entry{Mode: tc.mode}, AuditEntry{AuthCapability: tc.scope})
		if (err == nil) != tc.allowed {
			t.Fatalf("mode=%s scope=%s err=%v", tc.mode, tc.scope, err)
		}
	}
}
func TestScriptDirectQueueBypassIsRejected(t *testing.T) {
	st, req, _, _ := scriptFixture(t)
	spec := string(mustScriptJSON(scriptcatalog.Spec{Kind: scriptcatalog.Kind, ScriptID: req.ScriptID, ScriptSHA256: req.ScriptSHA256, Args: req.Args}))
	if _, _, err := st.CreateDesiredState("machine", req.Targets[0], scriptcatalog.Kind, req.ScriptID, spec, "test"); err == nil {
		t.Fatal("direct queue bypass accepted")
	}
}
func TestScriptCompletionRequiresMatchingMetadata(t *testing.T) {
	st, req, a, now := scriptFixture(t)
	preview, err := st.ScriptRun(req, false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	result, err := st.ScriptRun(req, true, "metadata-key", a)
	if err != nil {
		t.Fatal(err)
	}
	id := result.JobIDs[0]
	machine := req.Targets[0]
	token, err := st.ClaimJob(id, machine, now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.AdvanceJobByAgent(id, machine, token, deploy.Start, now); err != nil {
		t.Fatal(err)
	}
	if err = st.RecordVerification(id, machine, token, scriptcatalog.Kind, req.ScriptID, 0, "facts", "", true, now); err != nil {
		t.Fatal(err)
	}
	if _, err = st.AdvanceJobByAgent(id, machine, token, deploy.FinishWork, now); err != nil {
		t.Fatal(err)
	}
	if _, err = st.MarkSucceededIfVerified(id, now); err != ErrNoVerification {
		t.Fatalf("missing metadata must block success: %v", err)
	}
}

func TestScriptRunFanoutHasOneBoundedRequestAudit(t *testing.T) {
	st, req, actor, now := scriptFixture(t)
	for i := 1; i < 50; i++ {
		id := mustEnroll(t, st, fmt.Sprintf("probe-node-%02d", i), now)
		c := healthyCheckin(now)
		c.ScriptV1 = true
		if err := st.RecordCheckin(id, c, now); err != nil {
			t.Fatal(err)
		}
		req.Targets = append(req.Targets, id)
	}
	check := func(action AuditAction, wantCount int, result ScriptRunResult, replayed bool) {
		t.Helper()
		var count int
		if err := st.rdb.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=?`, action).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != wantCount {
			t.Fatalf("request audit count=%d want=%d for %s", count, wantCount, action)
		}
		rows, err := st.Audit("", 200)
		if err != nil {
			t.Fatal(err)
		}
		for _, row := range rows {
			if row.Action != action {
				continue
			}
			detail := row.Detail
			if replayed {
				detail = strings.TrimPrefix(detail, OperatorIdempotencyReplayPrefix)
			}
			if len(row.Detail) > auditMaxReason || !json.Valid([]byte(detail)) {
				t.Fatalf("audit is truncated or invalid JSON: %q", row.Detail)
			}
			var metadata struct {
				TargetCount   int    `json:"target_count"`
				TargetsDigest string `json:"targets_digest"`
				JobCount      int    `json:"job_count"`
				JobsDigest    string `json:"job_ids_digest"`
			}
			if err := json.Unmarshal([]byte(detail), &metadata); err != nil {
				t.Fatal(err)
			}
			if metadata.TargetCount != 50 || metadata.TargetsDigest != scriptcatalog.Digest(mustScriptJSON(result.Targets)) || metadata.JobCount != len(result.JobIDs) || metadata.JobsDigest != scriptcatalog.Digest(mustScriptJSON(result.JobIDs)) {
				t.Fatalf("audit lost complete fanout correlation: %+v", metadata)
			}
			if row.AuthSubject != actor.AuthSubject || row.MachineID != "" {
				t.Fatalf("request audit provenance %+v", row)
			}
			return
		}
		t.Fatal("missing request audit")
	}
	preview, err := st.ScriptRun(req, false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	check(AuditScriptPreview, 1, preview, false)
	req.PreviewDigest = preview.PreviewDigest
	applied, err := st.ScriptRun(req, true, "fanout-key", actor)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.JobIDs) != 50 {
		t.Fatalf("fanout created %d jobs", len(applied.JobIDs))
	}
	check(AuditScriptApply, 1, applied, false)
	replay, err := st.ScriptRun(req, true, "fanout-key", actor)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay %+v %v", replay, err)
	}
	check(AuditScriptApply, 2, replay, true)
	var jobs int
	if err := st.rdb.QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&jobs); err != nil || jobs != 50 {
		t.Fatalf("replay changed fanout: %d %v", jobs, err)
	}
}

func TestBATReportJobPreviewApply(t *testing.T) {
	st, req, actor, _ := scriptFixture(t)
	entry, _ := scriptcatalog.Lookup("bat-sweep-report-v1")
	req.ScriptID, req.ScriptSHA256 = entry.ID, entry.SHA256
	req.Args = json.RawMessage(`{"hosts":["sample-host"],"connector_tree_sha256":"` + strings.Repeat("a", 64) + `"}`)
	if _, err := st.ScriptRun(req, false, "", actor); err == nil {
		t.Fatal("operate principal accepted")
	}
	actor.AuthCapability = "admin"
	req.TimeoutSeconds = 600
	preview, err := st.ScriptRun(req, false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	result, err := st.ScriptRun(req, true, "bat-pilot", actor)
	if err != nil || len(result.JobIDs) != 1 {
		t.Fatalf("apply %+v %v", result, err)
	}
	req.TimeoutSeconds = 601
	if _, err := st.ScriptRun(req, false, "", actor); err == nil {
		t.Fatal("unbounded BAT timeout")
	}
	req.TimeoutSeconds = 600
	req.Args = json.RawMessage(`{"hosts":["bad.host"]}`)
	if _, err := st.ScriptRun(req, false, "", actor); err == nil {
		t.Fatal("invalid host accepted")
	}
}

func TestScriptApprovalBindsExecutionMode(t *testing.T) {
	st, req, audit, _ := scriptFixture(t)
	normalized, entry, err := normalizeScript(req)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := st.ScriptRun(req, false, "", audit)
	if err != nil {
		t.Fatal(err)
	}
	if preview.PreviewDigest != scriptModeBoundDigest(normalized, entry.Mode) {
		t.Fatal("preview did not bind catalog mode")
	}
	req.PreviewDigest = scriptModeBoundDigest(normalized, "write")
	if _, err := st.ScriptRun(req, true, "wrong-mode-approval", audit); err == nil {
		t.Fatal("approval for a different execution mode accepted")
	}
	req.PreviewDigest = preview.PreviewDigest
	if scriptModeBoundDigest(req, "read") == scriptModeBoundDigest(req, "write") {
		t.Fatal("request digest does not bind execution mode")
	}
	result, err := st.ScriptRun(req, true, "mode-bound-approval", audit)
	if err != nil {
		t.Fatal(err)
	}
	normalized.PreviewDigest = req.PreviewDigest
	var storedDigest string
	if err := st.DB().QueryRow(`SELECT request_digest FROM operator_idempotency WHERE idempotency_key=?`, "mode-bound-approval").Scan(&storedDigest); err != nil || storedDigest != "script-v2:"+scriptModeBoundDigest(normalized, "read") {
		t.Fatalf("request binding: %v", err)
	}
	job, err := st.Job(result.JobIDs[0])
	if err != nil {
		t.Fatal(err)
	}
	desired, err := st.DesiredState(job.DesiredID)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := scriptcatalog.Decode([]byte(desired.Spec))
	if err != nil || spec.ExecutionMode != "read" {
		t.Fatal("approved execution mode not stored")
	}
}

func TestScriptLegacyDigestReceiptReplay(t *testing.T) {
	for _, version := range []string{"legacy-request", "unversioned-mode-bound", "v2-rejects-legacy-fallback"} {
		t.Run(version, func(t *testing.T) {
			s, req, actor, _ := scriptFixture(t)
			preview, err := s.ScriptRun(req, false, "", actor)
			if err != nil {
				t.Fatal(err)
			}
			req.PreviewDigest = preview.PreviewDigest
			created, err := s.ScriptRun(req, true, "existing-script-key", actor)
			if err != nil {
				t.Fatal(err)
			}
			normalized, entry, err := normalizeScript(req)
			if err != nil {
				t.Fatal(err)
			}
			if version != "unversioned-mode-bound" {
				legacyPreview := normalized
				legacyPreview.PreviewDigest = ""
				req.PreviewDigest = "sha256:" + scriptcatalog.Digest(mustScriptJSON(legacyPreview))
				normalized.PreviewDigest = req.PreviewDigest
				created.PreviewDigest = req.PreviewDigest
			}
			digest := "sha256:" + scriptcatalog.Digest(mustScriptJSON(normalized))
			if version == "unversioned-mode-bound" {
				digest = scriptModeBoundDigest(normalized, entry.Mode)
			}
			if version == "v2-rejects-legacy-fallback" {
				digest = "script-v2:" + digest
			}
			if _, err := s.DB().Exec(`UPDATE operator_idempotency SET request_digest=?,response_json=? WHERE idempotency_key=?`, digest, string(mustScriptJSON(created)), "existing-script-key"); err != nil {
				t.Fatal(err)
			}
			replayed, err := s.ScriptRun(req, true, "existing-script-key", actor)
			if version == "v2-rejects-legacy-fallback" {
				if err == nil {
					t.Fatal("versioned receipt used legacy fallback")
				}
			} else {
				if err != nil || !replayed.Replayed || len(replayed.JobIDs) != 1 || replayed.JobIDs[0] != created.JobIDs[0] || replayed.PreviewDigest != created.PreviewDigest {
					t.Fatalf("legacy receipt not replayed: %v", err)
				}
				var replayAudits int
				if err := s.DB().QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action=? AND idempotency_key=? AND request_digest=? AND detail LIKE ?`, AuditScriptApply, "existing-script-key", digest, OperatorIdempotencyReplayPrefix+"%").Scan(&replayAudits); err != nil || replayAudits != 1 {
					t.Fatalf("legacy replay audit correlation=%d err=%v", replayAudits, err)
				}
				changed := req
				changed.Reason = "different request"
				if _, err := s.ScriptRun(changed, true, "existing-script-key", actor); err == nil {
					t.Fatal("changed request matched legacy receipt")
				}
				if version == "legacy-request" {
					if _, err := s.ScriptRun(req, true, "fresh-key", actor); err == nil {
						t.Fatal("legacy approval accepted for fresh execution")
					}
				}
			}
			var count int
			if err := s.DB().QueryRow(`SELECT COUNT(*) FROM jobs`).Scan(&count); err != nil || count != 1 {
				t.Fatalf("duplicate execution count=%d err=%v", count, err)
			}
		})
	}
}

func TestScriptTargetFailureReasons(t *testing.T) {
	for _, tc := range []struct{ name, query, want string }{
		{"retired", "", "retired"},
		{"no checkin", `DELETE FROM machine_checkins WHERE machine_id=?`, "no check-in yet"},
		{"disabled", `UPDATE machine_checkins SET jobs_enabled=0 WHERE machine_id=?`, "jobs disabled in latest check-in"},
		{"capability absent", `DELETE FROM machine_job_capabilities WHERE machine_id=?`, "script_v1 capability not advertised in latest check-in"},
		{"capability false", `UPDATE machine_job_capabilities SET supported=0 WHERE machine_id=?`, "script_v1 capability not advertised in latest check-in"},
		{"os", `UPDATE machine_registry SET os='unsupported' WHERE machine_id=?`, "OS 'unsupported' (family '') not allowed for this script (allowed: "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, req, a, _ := scriptFixture(t)
			if tc.name == "retired" {
				revision := int64(0)
				preview, err := st.PreviewOperatorMachineLifecycle(OperatorMachineLifecyclePreviewRequest{MachineID: req.Targets[0], DesiredState: MachineLifecycleRetired, ExpectedRevision: &revision})
				if err != nil {
					t.Fatal(err)
				}
				if _, err := st.ApplyOperatorMachineLifecycle(operatorLifecycleRequest(req.Targets[0], preview, "retire-target")); err != nil {
					t.Fatal(err)
				}
			} else if _, err := st.db.Exec(tc.query, req.Targets[0]); err != nil {
				t.Fatal(err)
			}
			_, err := st.ScriptRun(req, false, "", a)
			if err == nil || !strings.Contains(err.Error(), "probe-node: "+tc.want) {
				t.Fatalf("error = %v", err)
			}
			var rejection *OperatorRequestError
			if !errors.As(err, &rejection) || rejection.Code != "SCRIPT_INVALID" {
				t.Fatalf("error code = %v", err)
			}
			if tc.name == "no checkin" && strings.Contains(err.Error(), "latest check-in") {
				t.Fatal(err)
			}
		})
	}
}

func TestScriptTargetFailuresAggregateAndBoundJobs(t *testing.T) {
	st, req, a, now := scriptFixture(t)
	first := req.Targets[0]
	preview, err := st.ScriptRun(req, false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	out, err := st.ScriptRun(req, true, "active-fixture", a)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		_, err = st.db.Exec(`INSERT INTO jobs(job_id,machine_id,desired_id,revision,state,created_at) SELECT ?,machine_id,desired_id,revision,?,created_at FROM jobs WHERE job_id=?`, fmt.Sprintf("extra-%d", i), deploy.Running, out.JobIDs[0])
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err = st.db.Exec(`UPDATE machine_registry SET display_name='' WHERE machine_id=?`, first); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.Exec(`UPDATE machine_checkins SET jobs_enabled=0 WHERE machine_id=?`, first); err != nil {
		t.Fatal(err)
	}
	second := mustEnroll(t, st, "second-node", now)
	req.Targets = append(req.Targets, second, "missing-machine")
	_, err = st.ScriptRun(req, false, "", a)
	if err == nil {
		t.Fatal("accepted failing targets")
	}
	lines := strings.Split(err.Error(), "\n")
	if len(lines) != 3 {
		t.Fatalf("failures = %v", err)
	}
	joined := strings.Join(lines, "\n")
	for _, want := range []string{first + ": jobs disabled in latest check-in; 4 active job(s) (", "running/script_v1", "second-node: no check-in yet", "missing-machine: target not found"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q: %v", want, err)
		}
	}
	if strings.Count(joined, "/script_v1") != 3 {
		t.Fatalf("job examples not capped: %v", err)
	}
}

func TestScriptTargetsUseLatestCheckin(t *testing.T) {
	st, req, a, now := scriptFixture(t)
	latest := healthyCheckin(now.Add(time.Minute))
	disabled := false
	latest.JobsEnabled = &disabled
	latest.ScriptV1 = false
	if err := st.RecordCheckin(req.Targets[0], latest, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	_, err := st.ScriptRun(req, false, "", a)
	want := "probe-node: jobs disabled in latest check-in; script_v1 capability not advertised in latest check-in"
	if err == nil || err.Error() != want {
		t.Fatalf("error = %v", err)
	}
	latest = healthyCheckin(now.Add(2 * time.Minute))
	latest.ScriptV1 = true
	if err := st.RecordCheckin(req.Targets[0], latest, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ScriptRun(req, false, "", a); err != nil {
		t.Fatal(err)
	}
}

func TestScriptReasonsAcceptOperatorProse(t *testing.T) {
	_, req, _, _ := scriptFixture(t)
	for _, reason := range []string{"rotate disk on node1, per ticket #42", "node1.example.com: inspect /var/log", "中文，排查磁碟 #42", "  routine check  "} {
		req.Reason = reason
		normalized, _, err := normalizeScript(req)
		if err != nil || normalized.Reason != strings.TrimSpace(reason) {
			t.Fatalf("ordinary reason rejected: %v", err)
		}
	}
}

func TestFleetProbeV2DarwinDispatch(t *testing.T) {
	st, req, actor, now := scriptFixture(t)
	machine := req.Targets[0]
	if _, err := st.db.Exec("UPDATE machine_registry SET os='Darwin' WHERE machine_id=?", machine); err != nil {
		t.Fatal(err)
	}
	if _, err := st.ScriptRun(req, false, "", actor); err == nil {
		t.Fatal("Linux-only v1 accepted Darwin")
	}
	entry, _ := scriptcatalog.Lookup("fleet-probe-v2")
	req.ScriptID, req.ScriptSHA256 = entry.ID, entry.SHA256
	preview, err := st.ScriptRun(req, false, "", actor)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	result, err := st.ScriptRun(req, true, "darwin-probe", actor)
	if err != nil || len(result.JobIDs) != 1 {
		t.Fatalf("dispatch: %+v %v", result, err)
	}
	if _, err := st.ClaimJob(result.JobIDs[0], machine, now, time.Minute); err != nil {
		t.Fatal(err)
	}
}
