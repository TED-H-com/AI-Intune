package model

import "time"

// ReadinessConfig contains measurement targets, never execution instructions.
type ReadinessConfig struct {
	Path        string `json:"path"`
	SudoersPath string `json:"sudoers_path"`
	BackupUnit  string `json:"backup_unit"`
}
type ReadinessFacts struct {
	Config            ReadinessConfig  `json:"config"`
	ServiceUser       string           `json:"service_user"`
	Tailscale         *bool            `json:"tailscale"`
	Sudoers           *bool            `json:"sudoers"`
	SignedIn          map[string]*bool `json:"signed_in"`
	BackupPresent     *bool            `json:"backup_present"`
	BackupLastSuccess *time.Time       `json:"backup_last_success"`
}
