package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/teddashh/AI-Intune/internal/model"
	"regexp"
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
	Name       string `json:"name"`
	Status     string `json:"status"`
	NextAction string `json:"next_action"`
	Doc        string `json:"doc"`
}
type HostChecklist struct {
	DisplayName string                `json:"display_name"`
	MachineID   string                `json:"machine_id"`
	Config      model.ReadinessConfig `json:"config"`
	ReceivedAt  *time.Time            `json:"received_at"`
	Facts       *model.ReadinessFacts `json:"facts"`
	Items       []ReadinessItem       `json:"items"`
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
	var raw, received, measured string
	err = s.rdb.QueryRow(`SELECT payload,received_at,measured_at FROM observed_state WHERE machine_id=? AND kind='host_readiness' ORDER BY received_at DESC,rowid DESC LIMIT 1`, id).Scan(&raw, &received, &measured)
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
	add := func(name, status, action, doc string) {
		v.Items = append(v.Items, ReadinessItem{name, status, action, "https://github.com/TED-H-com/AI-Intune/blob/main/docs/" + doc})
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
	add("Agent check-in", status, "Check the agent service and reconnect; freshness limit is 10 minutes.", "runbooks/NEW-HOST.md")
	f := v.Facts
	if f == nil || v.ReceivedAt == nil || now.Sub(*v.ReceivedAt) > 15*time.Minute || now.Sub(parseTime(measured)) > 15*time.Minute || parseTime(measured).After(now.Add(time.Minute)) || f.Config != v.Config {
		f = &model.ReadinessFacts{}
	}
	status = "unknown"
	if v.Config.Path == "tailscale" {
		status = check(f.Tailscale)
	}
	add("Reachability ("+v.Config.Path+")", status, "Configure the access path below and verify SSH from the operator box. Only Tailscale has agent evidence.", "runbooks/OPERATOR-BOX-SSH.md")
	add("Scoped sudoers", check(f.Sudoers), "Configure the expected drop-in below; install the reviewed scoped policy on the host.", "runbooks/NEW-HOST.md")
	for _, name := range []string{"claude", "codex", "grok", "agy"} {
		add(name+" signed in", check(f.SignedIn[name]), "Sign in interactively as the agent service user, then wait for a fresh observation. Local configuration does not prove provider acceptance.", "FLEET-AI-CLIS.md")
	}
	var n int
	if err = s.rdb.QueryRow(`SELECT COUNT(*) FROM channel_bindings WHERE machine_id=?`, id).Scan(&n); err != nil {
		return v, err
	}
	status = "fail"
	if n > 0 {
		status = "pass"
	}
	add("Notification bindings", status, "Open Channels and bind a selected channel to this machine; send a test there.", "CHANNELS.md")
	add("Backup job", check(f.BackupPresent), "Configure the user backup service unit below and enable its timer on the host.", "runbooks/RESTORE-DRILL.md")
	status = "unknown"
	if f.BackupLastSuccess != nil {
		status = "pass"
		if now.Sub(*f.BackupLastSuccess) > 48*time.Hour || f.BackupLastSuccess.After(now.Add(time.Minute)) {
			status = "fail"
		}
	}
	add("Backup last completed OK", status, "Inspect the selected backup service and run a backup; completion must be within 48 hours.", "runbooks/RESTORE-DRILL.md")
	signedIn := map[string]*bool{}
	for _, name := range []string{"claude", "codex", "grok", "agy"} {
		signedIn[name] = f.SignedIn[name]
	}
	f.SignedIn = signedIn
	if !regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,63}[$]?$`).MatchString(f.ServiceUser) {
		f.ServiceUser = ""
	}
	// Keep the API projection limited to typed readiness facts; no credential prose.
	v.Facts = f
	return v, nil
}
