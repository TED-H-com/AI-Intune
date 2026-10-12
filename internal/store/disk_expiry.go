package store

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/schedulecron"
	"github.com/teddashh/AI-Intune/internal/scriptcatalog"
	"sort"
	"time"
)

func DiskExpiryScheduleTemplate(policyID, digest, machine string) ScheduleRequest {
	e, _ := scriptcatalog.Lookup("disk-quarantine-expire-v1")
	return ScheduleRequest{Name: "quarantine-expiry-" + scriptcatalog.Digest([]byte(machine + ":" + policyID))[:12], ScriptID: e.ID, ScriptSHA256: e.SHA256, Args: mustScriptJSON(map[string]string{"policy_id": policyID, "policy_digest": digest}), Targets: []string{machine}, Cron: "10 6 * * *", Enabled: true, CatchUp: false, Reason: "Expire previously human-approved quarantine after seven days"}
}
func expirySelectionTx(tx dbTx, machine string, policy string, digest string, now time.Time) (map[string][]string, int64, error) {
	rows, err := tx.Query(`SELECT q.manifest_id,q.item_id,a.policy_revision FROM disk_quarantine q JOIN ops_manifests m ON m.id=q.manifest_id JOIN ops_approvals a ON a.id=m.approval_id JOIN ops_policies p ON p.id=a.policy_id AND p.revision=a.policy_revision WHERE q.machine_id=? AND q.state='quarantined' AND q.expires_at<=? AND a.state='consumed' AND a.operation='quarantine' AND p.id=? AND p.digest=? AND p.superseded_at IS NULL ORDER BY q.expires_at,q.manifest_id,q.item_id LIMIT 100`, machine, fmtTime(now), policy, digest)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := map[string][]string{}
	var revision int64
	for rows.Next() {
		var id, item string
		if err = rows.Scan(&id, &item, &revision); err != nil {
			return nil, 0, err
		}
		out[id] = append(out[id], item)
	}
	return out, revision, rows.Err()
}
func recordExpiryJobTx(tx dbTx, job, machine string, args json.RawMessage, now time.Time) error {
	var a struct {
		ID     string `json:"policy_id"`
		Digest string `json:"policy_digest"`
	}
	_ = json.Unmarshal(args, &a)
	selection, revision, err := expirySelectionTx(tx, machine, a.ID, a.Digest, now)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`INSERT INTO disk_expiry_jobs VALUES (?,?,?,?,?,?,?)`, job, machine, a.ID, revision, a.Digest, string(mustScriptJSON(selection)), fmtTime(now))
	return err
}
func (s *Store) signedExpiryGrant(machine, job, digest string) (scriptcatalog.SignedDiskGrant, error) {
	var out scriptcatalog.SignedDiskGrant
	key := s.diskManifestSigner.Load()
	if key == nil || !s.DiskOpsWritesEnabled() {
		return out, operatorError("PRECONDITION_FAILED", "expiry authority unavailable")
	}
	tx, err := s.beginWrite(context.Background(), "expiry_grant")
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var id, stored, selectionRaw, specRaw, lease string
	var revision int64
	if err = tx.QueryRow(`SELECT x.policy_id,x.policy_revision,x.policy_digest,x.selection,d.spec,j.lease_expires_at FROM disk_expiry_jobs x JOIN jobs j ON j.job_id=x.job_id JOIN desired_state d ON d.desired_id=j.desired_id WHERE x.job_id=? AND x.machine_id=? AND j.state='running'`, job, machine).Scan(&id, &revision, &stored, &selectionRaw, &specRaw, &lease); err != nil {
		return out, operatorError("FORBIDDEN", "expiry job not assigned")
	}
	now := s.now().UTC()
	if stored != digest || !parseTime(lease).After(now) {
		return out, operatorError("PRECONDITION_FAILED", "expiry grant expired or mismatched")
	}
	spec, err := scriptcatalog.Decode([]byte(specRaw))
	e, _ := scriptcatalog.Lookup("disk-quarantine-expire-v1")
	if err != nil || spec.ScriptID != e.ID || spec.ScriptSHA256 != e.SHA256 || spec.ExecutionMode != "write" {
		return out, operatorError("PRECONDITION_FAILED", "unreviewed expiry job")
	}
	if err = s.diskSafeGateTx(tx, ScriptRunRequest{Args: spec.Args, Targets: []string{machine}}, e, true); err != nil {
		return out, err
	}
	var policy string
	if err = tx.QueryRow(`SELECT body FROM ops_policies WHERE id=? AND revision=? AND digest=? AND superseded_at IS NULL`, id, revision, digest).Scan(&policy); err != nil {
		return out, operatorError("PRECONDITION_FAILED", "expiry policy revoked")
	}
	var selection map[string][]string
	if err = json.Unmarshal([]byte(selectionRaw), &selection); err != nil {
		return out, err
	}
	ids := []string{}
	for id := range selection {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	manifests := [][]byte{}
	for _, id := range ids {
		var body string
		if err = tx.QueryRow(`SELECT m.body FROM ops_manifests m JOIN ops_approvals a ON a.id=m.approval_id WHERE m.id=? AND m.machine_id=? AND a.state='consumed' AND a.operation='quarantine' AND a.policy_digest=?`, id, machine, digest).Scan(&body); err != nil {
			return out, operatorError("PRECONDITION_FAILED", "original quarantine approval unavailable")
		}
		manifests = append(manifests, []byte(body))
	}
	expires := now.Add(15 * time.Second)
	if parseTime(lease).Before(expires) {
		expires = parseTime(lease)
	}
	grant := scriptcatalog.DiskGrant{Schema: "disk-grant/v1", Action: "expire", ScriptID: e.ID, ScriptSHA256: e.SHA256, MachineID: machine, JobID: job, ArgsDigest: "sha256:" + scriptcatalog.Digest(spec.Args), PolicyID: id, PolicyDigest: digest, Policy: []byte(policy), Manifests: manifests, Selection: selection, ExpiresAt: expires}
	out, err = scriptcatalog.SignDiskGrant(key, grant)
	if err != nil {
		return out, err
	}
	return out, tx.Commit()
}

func ensureExpiryScheduleTx(tx dbTx, a OpsApproval, now time.Time) error {
	req := DiskExpiryScheduleTemplate(a.PolicyID, a.PolicyDigest, a.MachineID)
	cron, _ := schedulecron.Parse(req.Cron)
	id := "expiry-" + scriptcatalog.Digest([]byte(a.MachineID + ":" + a.PolicyID))[:24]
	_, err := tx.Exec(`INSERT OR IGNORE INTO schedules(id,name,script_id,script_sha256,args,targets,cron,enabled,catch_up,created_by,created_at,updated_at,revision,next_run_at,execution_mode) VALUES (?,?,?,?,?,?,?,1,0,?,?,?,1,?,'write')`, id, req.Name, req.ScriptID, req.ScriptSHA256, string(req.Args), string(mustScriptJSON(req.Targets)), req.Cron, a.DecisionActor, fmtTime(now), fmtTime(now), fmtTime(cron.Next(now)))
	return err
}
