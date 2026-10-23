package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/operatorauth"
)

func monitorActor() AuditEntry {
	return AuditEntry{AuthSubject: "local-user:admin", AuthMethod: operatorauth.AuthMethodLocalAPI, AuthCapability: "admin", AuthDecision: string(operatorauth.Authorized)}
}
func monitorMachine(t *testing.T, st *Store, mode string) string {
	t.Helper()
	p, err := st.PreviewOperatorEnrollToken("monitor-fixture", 600, mode == model.ExecutionMonitorOnly)
	if err != nil {
		t.Fatal(err)
	}
	req := operatorEnrollTestRequest(p)
	req.MonitorOnly = mode == model.ExecutionMonitorOnly
	out, err := st.ApplyOperatorEnrollToken(req)
	if err != nil {
		t.Fatal(err)
	}
	return out.MachineID
}
func TestExecutionPolicyEnrollmentAndDispatchRefusals(t *testing.T) {
	st := newOperatorEnrollTestStore(t)
	id := monitorMachine(t, st, model.ExecutionMonitorOnly)
	policy, err := st.MachineExecutionPolicy(id)
	if err != nil || policy.Mode != model.ExecutionMonitorOnly || policy.Revision != 1 {
		t.Fatalf("policy=%+v err=%v", policy, err)
	}
	if st.MachineExecutionAllowed(id) == nil {
		t.Fatal("monitor execution allowed")
	}
	desired, rev, err := st.CreateDesiredState("machine", id, "openclaw", "openclaw", `{}`, "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.CreateJob(id, desired, rev, NewJob{}); err == nil {
		t.Fatal("job accepted")
	}
	if _, _, err = st.NextJobForMachine(id); err == nil {
		t.Fatal("poll accepted")
	}
	if _, err = st.ClaimJob("missing", id, st.now(), time.Minute); err == nil {
		t.Fatal("claim accepted")
	}
	if _, err = st.StartSignin(context.Background(), id, "claude", 1, monitorActor()); err == nil {
		t.Fatal("sign-in accepted")
	}
	if commands := st.SigninCommands(id); len(commands) != 0 {
		t.Fatal("sign-in dispatched")
	}
	if _, err = st.ApproveDiskSetup(id, model.DiskJob{}, monitorActor()); err == nil {
		t.Fatal("disk operation accepted")
	}
	if _, err = st.DiskManifestForJob(id, "missing", "missing", "missing"); err == nil {
		t.Fatal("root grant accepted")
	}
	// The database is the final guard, independent of the adapter and job vocabulary.
	if _, err = st.db.Exec(`INSERT INTO agent_sessions(session_id,machine_id,operator_tailnet_user_id,operator_tailnet_user_login,opened_at) VALUES('session',?,'user','operator','2026-10-19T00:00:00Z')`, id); err == nil || !strings.Contains(err.Error(), "machine execution is blocked") {
		t.Fatal("raw session insert allowed", err)
	}
	if _, err = st.db.Exec(`INSERT INTO schedules(id,name,script_id,script_sha256,args,targets,cron,tz,enabled,revision,created_at,updated_at,created_by,next_run_at) VALUES('test','test','test','test','{}',?,'* * * * *','UTC',0,1,?,?,'operator','2026-10-20T00:00:00Z')`, `["`+id+`"]`, fmtTime(st.now()), fmtTime(st.now())); err == nil || !strings.Contains(err.Error(), "machine execution is blocked") {
		t.Fatal("monitor schedule accepted", err)
	}
}
func TestExecutionPolicyPreviewApplyAuditReplayAndMigrationDefaults(t *testing.T) {
	st := newOperatorEnrollTestStore(t)
	id := monitorMachine(t, st, model.ExecutionManaged)
	p, err := st.MachineExecutionPolicy(id)
	if err != nil || p.Mode != model.ExecutionManaged || p.Revision != 1 {
		t.Fatalf("default=%+v %v", p, err)
	}
	req := ExecutionPolicyRequest{MachineID: id, Mode: model.ExecutionMonitorOnly, Reason: "protect appliance", ExpectedRevision: 1, Audit: monitorActor()}
	preview, err := st.ManageExecutionPolicy(req, false)
	if err != nil {
		t.Fatal(err)
	}
	p, _ = st.MachineExecutionPolicy(id)
	if p.Mode != model.ExecutionManaged {
		t.Fatal("preview mutated policy")
	}
	req.PreviewDigest = preview.PreviewDigest
	req.IdempotencyKey = "profile-test"
	changed, err := st.ManageExecutionPolicy(req, true)
	if err != nil || changed.Mode != model.ExecutionMonitorOnly || changed.Revision != 2 {
		t.Fatalf("change=%+v %v", changed, err)
	}
	replay, err := st.ManageExecutionPolicy(req, true)
	if err != nil || !replay.Replayed {
		t.Fatalf("replay=%+v %v", replay, err)
	}
	req.IdempotencyKey = "stale-test"
	if _, err = st.ManageExecutionPolicy(req, true); err == nil {
		t.Fatal("stale preview accepted")
	}
	req.Audit.AuthMethod = operatorauth.AuthMethodServiceToken
	if _, err = st.ManageExecutionPolicy(req, false); err == nil {
		t.Fatal("automation changed profile")
	}
	var audits int
	if err = st.db.QueryRow(`SELECT count(*) FROM audit_log WHERE machine_id=? AND action='machine-execution-policy-apply'`, id).Scan(&audits); err != nil || audits < 3 {
		t.Fatalf("audit=%d %v", audits, err)
	}
}

func TestMonitorOnlyRefusesScriptAndSchedulePreviewApply(t *testing.T) {
	st, req, a, _ := scriptFixture(t)
	preview, err := st.ScriptRun(req, false, "", a)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	if _, err := st.db.Exec(`UPDATE machine_registry SET execution_policy='monitor_only' WHERE machine_id=?`, req.Targets[0]); err != nil {
		t.Fatal(err)
	}
	for _, apply := range []bool{false, true} {
		if _, err := st.ScriptRun(req, apply, "blocked-script", a); err == nil || !strings.Contains(err.Error(), "monitor only") {
			t.Fatalf("script apply=%v err=%v", apply, err)
		}
		schedule := ScheduleRequest{Name: "blocked-check", ScriptID: req.ScriptID, ScriptSHA256: req.ScriptSHA256, Args: req.Args, Targets: req.Targets, Cron: "*/5 * * * *", Enabled: false, Reason: req.Reason}
		if _, err := st.ScheduleManage(schedule, "upsert", apply, "blocked-schedule", a); err == nil {
			t.Fatal("monitor schedule accepted")
		}
	}
	var jobs int
	if err := st.db.QueryRow(`SELECT count(*) FROM jobs`).Scan(&jobs); err != nil || jobs != 0 {
		t.Fatalf("jobs=%d err=%v", jobs, err)
	}
}
func TestMonitorOnlyPausesSchedulesAndNeverRestartsThem(t *testing.T) {
	st, schedule, _, now := createTestSchedule(t)
	id := schedule.Targets[0]
	// Explicit modern support is required for an enrolled machine.
	req := ExecutionPolicyRequest{MachineID: id, Mode: model.ExecutionMonitorOnly, Reason: "protect appliance", ExpectedRevision: 1, Audit: monitorActor()}
	if _, err := st.ManageExecutionPolicy(req, false); err == nil {
		t.Fatal("old agent accepted")
	}
	checkin := healthyCheckin(now.Add(time.Second))
	checkin.ExecutionPolicyV1 = true
	checkin.MonitorOnlySupported = true
	if err := st.RecordCheckin(id, checkin, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	preview, err := st.ManageExecutionPolicy(req, false)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	req.IdempotencyKey = "pause-profile"
	if _, err = st.ManageExecutionPolicy(req, true); err != nil {
		t.Fatal(err)
	}
	paused, err := st.ScheduleGet(schedule.ID)
	if err != nil || paused.Enabled || paused.PausedReason != "machine_monitor_only" {
		t.Fatalf("schedule=%+v %v", paused, err)
	}
	if err = st.TickSchedules(schedule.NextRunAt); err != nil {
		t.Fatal(err)
	}
	var jobs int
	_ = st.db.QueryRow(`SELECT count(*) FROM jobs`).Scan(&jobs)
	if jobs != 0 {
		t.Fatal("schedule dispatched")
	}
	req.Mode = model.ExecutionManaged
	req.ExpectedRevision = 2
	req.IdempotencyKey = "restore-profile"
	preview, err = st.ManageExecutionPolicy(req, false)
	if err != nil {
		t.Fatal(err)
	}
	req.PreviewDigest = preview.PreviewDigest
	if _, err = st.ManageExecutionPolicy(req, true); err != nil {
		t.Fatal(err)
	}
	paused, _ = st.ScheduleGet(schedule.ID)
	if paused.Enabled {
		t.Fatal("restore enabled schedule")
	}
}
func TestMonitorOnlyTokenRejectsOldAgentWithoutConsumingTicket(t *testing.T) {
	st := newOperatorEnrollTestStore(t)
	p, err := st.PreviewOperatorEnrollToken("protected-enrollment", 600, true)
	if err != nil {
		t.Fatal(err)
	}
	req := operatorEnrollTestRequest(p)
	req.MonitorOnly = true
	token, err := st.ApplyOperatorEnrollToken(req)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := model.EnrollRequest{SchemaVersion: model.SchemaVersion, EnrollToken: token.EnrollmentToken, Hostname: "appliance", OS: "linux", Arch: "amd64", UnixUser: "agent"}
	if _, _, err = st.RedeemEnrollToken(token.EnrollmentToken, enrollment, st.now()); err == nil {
		t.Fatal("old agent enrolled")
	}
	enrollment.ExecutionPolicyV1 = true
	if _, _, err = st.RedeemEnrollToken(token.EnrollmentToken, enrollment, st.now()); err == nil {
		t.Fatal("unsafe applier enrolled")
	}
	enrollment.MonitorOnlySupported = true
	if _, _, err = st.RedeemEnrollToken(token.EnrollmentToken, enrollment, st.now()); err != nil {
		t.Fatal("modern agent enrollment failed", err)
	}
}

func TestMonitorOnlyRefusesTerminalAndSigninCodeRelay(t *testing.T) {
	st, id := signinFixture(t)
	session, err := st.StartSignin(context.Background(), id, "agy", 1, monitorActor())
	if err != nil {
		t.Fatal(err)
	}
	_ = st.SigninCommands(id)
	if err = st.UpdateSignin(id, model.SigninUpdate{ID: session.ID, State: "waiting_for_code"}); err != nil {
		t.Fatal(err)
	}
	if _, err = st.db.Exec(`UPDATE machine_registry SET execution_policy='monitor_only' WHERE machine_id=?`, id); err != nil {
		t.Fatal(err)
	}
	if err = st.SigninAction(context.Background(), session.ID, "code", "fixture-code", monitorActor()); err == nil || !strings.Contains(err.Error(), "monitor only") {
		t.Fatal("code accepted", err)
	}
	delivered := 0
	st.SetSigninTransport(func(string, model.SigninCommand) error { delivered++; return nil })
	st.DispatchSignins(id)
	if delivered != 0 || len(st.SigninCommands(id)) != 0 {
		t.Fatal("sign-in relay dispatched")
	}
	if _, err = st.StartSignin(context.Background(), id, "claude", 1, monitorActor()); err == nil || !strings.Contains(err.Error(), "monitor only") {
		t.Fatal("start accepted", err)
	}
	req := openAgentSessionRequest("protected-session", id, "user", "fixture", "monitor-session")
	if _, err = st.OpenAgentSession(req); err == nil || !strings.Contains(err.Error(), "monitor only") {
		t.Fatal("terminal accepted", err)
	}
	disk := model.DiskJob{Device: "/dev/sdb", Serial: "fixture", SizeBytes: 2 << 30, Model: "Fixture", MountPoint: "/data", FSType: "ext4", Label: "data", Owner: "agent"}
	if _, err = st.ApproveDiskSetup(id, disk, monitorActor()); err == nil || !strings.Contains(err.Error(), "monitor only") {
		t.Fatal("disk accepted", err)
	}
}

func TestMonitorOnlyRefusesRootApprovalAndTimerHandoff(t *testing.T) {
	st, approval, _ := approvalFixture(t)
	preview, err := st.OpsApprovalDecision(OpsApprovalDecisionRequest{ID: approval.ID, Decision: "approved", Reason: "review exact operation"}, false, "", diskAdmin())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = st.DB().Exec(`UPDATE machine_registry SET execution_policy='monitor_only' WHERE machine_id=?`, approval.MachineID); err != nil {
		t.Fatal(err)
	}
	for _, apply := range []bool{false, true} {
		if _, err = st.OpsApprovalDecision(preview.Request, apply, "blocked-approval", diskAdmin()); err == nil || !strings.Contains(err.Error(), "monitor only") {
			t.Fatalf("approval apply=%v err=%v", apply, err)
		}
	}
	if _, err = st.DecideOpsApproval(approval, true, diskAdmin()); err == nil || !strings.Contains(err.Error(), "monitor only") {
		t.Fatal("trusted approval accepted", err)
	}
	approval.ID = "blocked-approval"
	if _, err = st.CreateOpsApproval(approval, diskAdmin()); err == nil || !strings.Contains(err.Error(), "monitor only") {
		t.Fatal("approval creation accepted", err)
	}
	for _, action := range []string{"handoff", "rollback"} {
		if _, err = st.DiskOwnershipManage(DiskOwnershipRequest{MachineID: approval.MachineID, Scope: "user", Action: action, Reason: "review timer ownership"}, false, "", diskAdmin()); err == nil || !strings.Contains(err.Error(), "monitor only") {
			t.Fatal("timer operation accepted", action, err)
		}
	}
	var state string
	if err = st.DB().QueryRow(`SELECT state FROM ops_approvals WHERE id='approval-1'`).Scan(&state); err != nil || state != "pending" {
		t.Fatal("approval changed", state, err)
	}
}

func TestExecutionPolicyMigrationKeepsExistingMachineManaged(t *testing.T) {
	st := newTestStore(t)
	id := mustEnroll(t, st, "legacy-profile-machine", time.Now().UTC())
	job := newJobForDeployTest(t, st, id)
	rows, err := st.db.Query(`SELECT name FROM sqlite_master WHERE type='trigger' AND name LIKE 'execution_%'`)
	if err != nil {
		t.Fatal(err)
	}
	names := []string{}
	for rows.Next() {
		var name string
		if err = rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	rows.Close()
	for _, name := range names {
		if _, err = st.db.Exec(`DROP TRIGGER "` + name + `"`); err != nil {
			t.Fatal(err)
		}
	}
	for _, column := range []string{"execution_policy", "execution_policy_revision", "execution_policy_supported", "execution_policy_observed_revision"} {
		if _, err = st.db.Exec(`ALTER TABLE machine_registry DROP COLUMN ` + column); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 2; i++ {
		if err = addMissingColumns(st.db); err != nil {
			t.Fatal(err)
		}
	}
	if err = installExecutionPolicyGuards(st.db); err != nil {
		t.Fatal(err)
	}
	p, err := st.MachineExecutionPolicy(id)
	if err != nil || p.Mode != model.ExecutionManaged || p.Revision != 1 || p.Supported {
		t.Fatalf("migrated=%+v %v", p, err)
	}
	if _, err = st.ClaimJob(job, id, time.Now().UTC(), time.Minute); err != nil {
		t.Fatal("legacy managed dispatch changed", err)
	}
}
