package model

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// HostProfile is data with a closed vocabulary. Nil means do not manage.
// Field order is the canonical digest order, shared with the root applier.
type HostProfile struct {
	LidIgnore          *bool   `json:"lid_ignore,omitempty"`
	DisableSleep       *bool   `json:"disable_sleep,omitempty"`
	PowerProfile       *string `json:"power_profile,omitempty"`
	WifiPowerSaveOff   *bool   `json:"wifi_power_save_off,omitempty"`
	JournaldMaxMB      *int    `json:"journald_max_mb,omitempty"`
	UnattendedUpgrades *bool   `json:"unattended_upgrades,omitempty"`
	ScopedSudoers      *bool   `json:"scoped_sudoers,omitempty"`
	Linger             *bool   `json:"linger,omitempty"`
	RootDiskCleanTimer *bool   `json:"root_disk_clean_timer,omitempty"`
}

func (p HostProfile) Validate() error {
	if p.PowerProfile != nil && *p.PowerProfile != "performance" && *p.PowerProfile != "balanced" && *p.PowerProfile != "power-saver" {
		return fmt.Errorf("choose performance, balanced or power-saver")
	}
	if p.JournaldMaxMB != nil && (*p.JournaldMaxMB < 100 || *p.JournaldMaxMB > 4096) {
		return fmt.Errorf("journal size must be 100–4096 MB")
	}
	return nil
}
func (p HostProfile) Canonical() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
func (p HostProfile) Digest() (string, error) {
	b, err := p.Canonical()
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
func ParseHostProfile(b []byte) (HostProfile, error) {
	var p HostProfile
	if len(b) > 64<<10 || bytes.Equal(bytes.TrimSpace(b), []byte("null")) {
		return p, fmt.Errorf("invalid host profile")
	}
	scan := json.NewDecoder(bytes.NewReader(b))
	token, err := scan.Token()
	if err != nil || token != json.Delim('{') {
		return p, fmt.Errorf("expected a profile object")
	}
	seen := map[string]bool{}
	for scan.More() {
		key, err := scan.Token()
		if err != nil {
			return p, err
		}
		name, ok := key.(string)
		if !ok || seen[name] {
			return p, fmt.Errorf("duplicate profile field")
		}
		switch name {
		case "lid_ignore", "disable_sleep", "power_profile", "wifi_power_save_off", "journald_max_mb", "unattended_upgrades", "scoped_sudoers", "linger", "root_disk_clean_timer":
		default:
			return p, fmt.Errorf("unknown profile field")
		}
		seen[name] = true
		var value json.RawMessage
		if err = scan.Decode(&value); err != nil {
			return p, err
		}
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	var tail any
	if err := d.Decode(&tail); err != io.EOF {
		return p, fmt.Errorf("expected one profile")
	}
	return p, p.Validate()
}

type HostApplyItem struct {
	Status string `json:"status"`
	Detail string `json:"detail"`
}
type HostApplyResult struct {
	Schema         string                   `json:"schema"`
	ProfileDigest  string                   `json:"profile_digest"`
	AppliedAt      time.Time                `json:"applied_at"`
	Items          map[string]HostApplyItem `json:"items"`
	RebootRequired bool                     `json:"reboot_required"`
}

// ValidHostApplyResult bounds the additive host report before relaying or showing it.
func ValidHostApplyResult(r *HostApplyResult) bool {
	if r == nil || r.Schema != "clawctl-fleet-apply/v1" || r.AppliedAt.IsZero() || len(r.ProfileDigest) > 71 || len(r.Items) == 0 || len(r.Items) > 9 {
		return false
	}
	if len(r.Items) == 1 {
		if v, ok := r.Items["profile"]; ok {
			return v.Status == "failed" && len(v.Detail) <= 256 && r.ProfileDigest == ""
		}
	}
	if len(r.Items) != 9 || len(r.ProfileDigest) != 71 {
		return false
	}
	allowed := map[string]bool{"lid_ignore": true, "disable_sleep": true, "power_profile": true, "wifi_power_save_off": true, "journald_max_mb": true, "unattended_upgrades": true, "scoped_sudoers": true, "linger": true, "root_disk_clean_timer": true, "profile": true}
	for name, v := range r.Items {
		if !allowed[name] || len(v.Detail) > 256 {
			return false
		}
		switch v.Status {
		case "ok", "changed", "failed", "unsupported", "unmanaged":
		default:
			return false
		}
	}
	return true
}
