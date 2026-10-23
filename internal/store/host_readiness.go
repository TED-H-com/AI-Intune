package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"regexp"
	"strings"
	"time"
)

func (s *Store) HostReadinessConfig(id string) (model.ReadinessConfig, error) {
	c := model.ReadinessConfig{}
	var raw string
	err := s.rdb.QueryRow(`SELECT config FROM host_readiness_config WHERE machine_id=?`, id).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	err = json.Unmarshal([]byte(raw), &c)
	return c, err
}
func (s *Store) SaveHostReadinessConfig(id string, c model.ReadinessConfig, audits ...AuditEntry) error {
	if c.Path != "" && c.Path != "tailscale" && c.Path != "cloudflare" && c.Path != "jump_host" && c.Path != "direct" {
		return fmt.Errorf("invalid access path")
	}
	if c.SudoersPath != "" && (!regexp.MustCompile(`^/etc/sudoers.d/[A-Za-z0-9_-]+$`).MatchString(c.SudoersPath)) {
		return fmt.Errorf("invalid scoped drop-in path")
	}
	if c.BackupUnit != "" && !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.service$`).MatchString(c.BackupUnit) {
		return fmt.Errorf("use the backup service unit triggered by its timer")
	}
	var units []string
	if c.ExpectedUserUnits != "" {
		units = strings.Split(c.ExpectedUserUnits, ",")
	}
	if err := (model.FleetReadinessProfile{ExpectedUserUnits: units}).Validate(); err != nil {
		return err
	}
	raw, _ := json.Marshal(c)
	tx, err := s.beginWrite(context.Background(), "host_readiness_config")
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.Exec(`INSERT INTO host_readiness_config(machine_id,config) VALUES (?,?) ON CONFLICT(machine_id) DO UPDATE SET config=excluded.config`, id, string(raw))
	if err != nil {
		return err
	}
	for _, a := range audits {
		a.Action = AuditAction("host_readiness_config")
		a.MachineID = id
		a.Subject = id
		a.OK = true
		if err = s.recordAudit(tx, a); err != nil {
			return err
		}
	}
	return tx.Commit()
}

type ReadinessItem struct {
	Key        string `json:"key"`
	Owner      string `json:"owner"`
	Bucket     string `json:"bucket"`
	Name       string `json:"name"`
	Status     string `json:"status"`
	NextAction string `json:"next_action"`
	Doc        string `json:"doc"`
}
type HostChecklist struct {
	ReadyDisks      int                   `json:"ready_disks"`
	NeedsYou        int                   `json:"needs_you"`
	Auto            int                   `json:"auto"`
	Done            int                   `json:"done"`
	EffectiveConfig model.ReadinessConfig `json:"effective_config"`
	DisplayName     string                `json:"display_name"`
	MachineID       string                `json:"machine_id"`
	Config          model.ReadinessConfig `json:"config"`
	ReceivedAt      *time.Time            `json:"received_at"`
	Facts           *model.ReadinessFacts `json:"facts"`
	Items           []ReadinessItem       `json:"items"`
}

func (s *Store) HostChecklist(id string, now time.Time) (HostChecklist, error) {
	v := HostChecklist{MachineID: id, DisplayName: s.DisplayName(id)}
	var exists string
	err := s.rdb.QueryRow(`SELECT machine_id FROM machine_registry WHERE machine_id=?`, id).Scan(&exists)
	if errors.Is(err, sql.ErrNoRows) {
		return v, ErrNotFound
	}
	if err != nil {
		return v, err
	}
	var lastCheckin sql.NullString
	if err = s.rdb.QueryRow(`SELECT MAX(received_at) FROM machine_checkins WHERE machine_id=?`, id).Scan(&lastCheckin); err != nil {
		return v, err
	}
	v.Config, err = s.HostReadinessConfig(id)
	if err != nil {
		return v, err
	}
	profile, err := s.FleetReadinessProfile()
	if err != nil {
		return v, err
	}
	v.EffectiveConfig = profile.Effective(v.Config)
	var raw, received, measured string
	err = s.rdb.QueryRow(`SELECT payload,received_at,measured_at FROM observed_latest WHERE machine_id=? AND kind='host_readiness' ORDER BY received_at DESC,measured_at DESC,observation_sequence DESC LIMIT 1`, id).Scan(&raw, &received, &measured)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return v, err
	}
	if err == nil {
		if err = json.Unmarshal([]byte(raw), &v.Facts); err != nil {
			return v, err
		}
		t := parseTime(received)
		v.ReceivedAt = &t
	}
	add := func(key, name, status, action, doc string) {
		v.Items = append(v.Items, ReadinessItem{Key: key, Name: name, Status: status, NextAction: action, Doc: "https://github.com/TED-H-com/AI-Intune/blob/main/docs/" + doc})
	}
	check := func(b *bool) string {
		if b == nil {
			return "unknown"
		}
		if *b {
			return "pass"
		}
		return "fail"
	}
	status := "unknown"
	if lastCheckin.Valid && !parseTime(lastCheckin.String).IsZero() {
		status = "pass"
		if now.Sub(parseTime(lastCheckin.String)) > 10*time.Minute {
			status = "fail"
		}
	}
	add("checkin", "Agent check-in", status, "Check the agent service and reconnect; freshness limit is 10 minutes.", "runbooks/NEW-HOST.md")
	f := v.Facts
	if f == nil || v.ReceivedAt == nil || now.Sub(*v.ReceivedAt) > 15*time.Minute || now.Sub(parseTime(measured)) > 15*time.Minute || parseTime(measured).After(now.Add(time.Minute)) || f.Config != v.EffectiveConfig {
		f = &model.ReadinessFacts{}
	}
	status = "unknown"
	if v.EffectiveConfig.Path == "tailscale" {
		status = check(f.Tailscale)
	}
	add("reachability", "Reachability ("+v.EffectiveConfig.Path+")", status, "Configure the access path below and verify SSH from the operator box. Only Tailscale has agent evidence.", "runbooks/OPERATOR-BOX-SSH.md")
	add("sudoers", "Scoped sudoers", check(f.Sudoers), "Configure the expected drop-in below; install the reviewed scoped policy on the host.", "runbooks/NEW-HOST.md")
	clis := profile.ExpectedCLIs
	if len(clis) == 0 {
		clis = []string{"claude", "codex", "grok", "agy"}
	}
	for _, name := range clis {
		add("signin:"+name, name+" signed in", check(f.SignedIn[name]), "Sign in interactively as the agent service user, then wait for the agent to report the sign-in status.", "FLEET-AI-CLIS.md")
	}
	var n int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM channel_bindings WHERE machine_id=?`, id).Scan(&n); err != nil {
		return v, err
	}
	status = "fail"
	if n > 0 {
		status = "pass"
	}
	add("notifications", "Notification bindings", status, "Open Channels and bind a selected channel to this machine; send a test there.", "CHANNELS.md")
	add("backup_unit", "Backup job", check(f.BackupPresent), "Configure the user backup service unit below and enable its timer on the host.", "runbooks/RESTORE-DRILL.md")
	status = "unknown"
	if f.BackupLastSuccess != nil {
		status = "pass"
		if now.Sub(*f.BackupLastSuccess) > 48*time.Hour || f.BackupLastSuccess.After(now.Add(time.Minute)) {
			status = "fail"
		}
	}
	add("backup_recent", "Backup last completed OK", status, "Inspect the selected backup service and run a backup; completion must be within 48 hours.", "runbooks/RESTORE-DRILL.md")
	for _, unit := range strings.Split(v.EffectiveConfig.ExpectedUserUnits, ",") {
		if !model.ValidUserUnit(unit) {
			continue
		}
		u := f.Units[unit]
		status := "unknown"
		if u.Loaded != nil {
			status = "fail"
			if model.UnitOK(u) {
				status = "pass"
			}
		}
		add("unit:"+unit, unit+" on", status, "Wait for the next report.", "runbooks/NEW-HOST.md")
	}
	// Only expose configured, validated units and bounded remediation metadata.
	units := map[string]model.UnitFact{}
	for _, unit := range strings.Split(v.EffectiveConfig.ExpectedUserUnits, ",") {
		if model.ValidUserUnit(unit) {
			if u, ok := f.Units[unit]; ok {
				if u.Remediation != nil {
					r := *u.Remediation
					r.Reason = model.SafeReadinessReason(r.Reason)
					if r.Action != "enable --now" && r.Action != "start" {
						r.Action = ""
					}
					u.Remediation = &r
				}
				units[unit] = u
			}
		}
	}
	f.Units = units
	for i := range v.Items {
		item := &v.Items[i]
		*item = classifyReadiness(*item, v.EffectiveConfig, f.Units)
		switch item.Bucket {
		case "done":
			v.Done++
		case "auto":
			v.Auto++
		case "needs_you":
			v.NeedsYou++
		}
	}
	signedIn := map[string]*bool{}
	for _, name := range []string{"claude", "codex", "grok", "agy"} {
		signedIn[name] = f.SignedIn[name]
	}
	f.SignedIn = signedIn
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}[$]?$`).MatchString(f.ServiceUser) {
		f.ServiceUser = ""
	}
	disks, err := s.MachineDisks(id)
	if err != nil {
		return v, err
	}
	for _, d := range disks.Devices {
		if model.UnusedDisk(d) {
			active := false
			for _, j := range disks.Jobs {
				if j.Job.Device == d.Path && (j.State == "pending" || j.State == "delivered") {
					active = true
				}
			}
			if !active {
				v.ReadyDisks++
			}
		}
	}
	// Keep the API projection limited to typed readiness facts; no credential prose.
	v.Facts = f
	return v, nil
}
