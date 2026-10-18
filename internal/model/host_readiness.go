package model

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"
)

// ReadinessConfig contains validated targets and an explicit user-unit repair opt-in.
type ReadinessConfig struct {
	ExpectedUserUnits string `json:"expected_user_units"`
	AutoRemediate     bool   `json:"auto_remediate"`
	Path              string `json:"path"`
	SudoersPath       string `json:"sudoers_path"`
	BackupUnit        string `json:"backup_unit"`
}
type ReadinessFacts struct {
	Units             map[string]UnitFact `json:"units"`
	Config            ReadinessConfig     `json:"config"`
	ServiceUser       string              `json:"service_user"`
	Tailscale         *bool               `json:"tailscale"`
	Sudoers           *bool               `json:"sudoers"`
	SignedIn          map[string]*bool    `json:"signed_in"`
	BackupPresent     *bool               `json:"backup_present"`
	BackupLastSuccess *time.Time          `json:"backup_last_success"`
}

type UnitFact struct {
	Oneshot     *bool        `json:"oneshot,omitempty"`
	Failed      *bool        `json:"failed,omitempty"`
	Masked      *bool        `json:"masked,omitempty"`
	Disabled    *bool        `json:"disabled,omitempty"`
	Loaded      *bool        `json:"loaded"`
	Enabled     *bool        `json:"enabled"`
	Active      *bool        `json:"active"`
	Remediation *Remediation `json:"remediation,omitempty"`
}
type Remediation struct {
	At     time.Time `json:"at"`
	Action string    `json:"action"`
	OK     bool      `json:"ok"`
	Reason string    `json:"reason"`
}
type FleetReadinessProfile struct {
	Path                   string   `json:"path"`
	SudoersPath            string   `json:"sudoers_path"`
	BackupUnit             string   `json:"backup_unit"`
	ExpectedCLIs           []string `json:"expected_clis"`
	ExpectedUserUnits      []string `json:"expected_user_units"`
	AutoRemediateUserUnits bool     `json:"auto_remediate_user_units"`
}

var userUnitName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}\.(service|timer)$`)

func ValidUserUnit(name string) bool { return userUnitName.MatchString(name) }
func (p FleetReadinessProfile) Validate() error {
	if p.Path != "" && p.Path != "tailscale" && p.Path != "cloudflare" && p.Path != "jump_host" && p.Path != "direct" {
		return fmt.Errorf("invalid access path")
	}
	if p.SudoersPath != "" && !regexp.MustCompile(`^/etc/sudoers.d/[A-Za-z0-9_-]+$`).MatchString(p.SudoersPath) {
		return fmt.Errorf("invalid scoped drop-in path")
	}
	if p.BackupUnit != "" && (!ValidUserUnit(p.BackupUnit) || !strings.HasSuffix(p.BackupUnit, ".service")) {
		return fmt.Errorf("use the backup service unit triggered by its timer")
	}
	if len(p.ExpectedCLIs) > 4 || len(p.ExpectedUserUnits) > 16 {
		return fmt.Errorf("too many readiness targets")
	}
	seen := map[string]bool{}
	for _, cli := range p.ExpectedCLIs {
		if seen[cli] || (cli != "claude" && cli != "codex" && cli != "grok" && cli != "agy") {
			return fmt.Errorf("invalid expected CLI")
		}
		seen[cli] = true
	}
	seen = map[string]bool{}
	for _, unit := range p.ExpectedUserUnits {
		if !ValidUserUnit(unit) || seen[unit] {
			return fmt.Errorf("invalid expected user unit")
		}
		seen[unit] = true
	}
	return nil
}
func (p FleetReadinessProfile) Effective(c ReadinessConfig) ReadinessConfig {
	if c.Path == "" {
		c.Path = p.Path
	}
	if c.SudoersPath == "" {
		c.SudoersPath = p.SudoersPath
	}
	if c.BackupUnit == "" {
		c.BackupUnit = p.BackupUnit
	}
	units := append([]string(nil), p.ExpectedUserUnits...)
	sort.Strings(units)
	if c.ExpectedUserUnits == "" {
		c.ExpectedUserUnits = strings.Join(units, ",")
	} else {
		units = strings.Split(c.ExpectedUserUnits, ",")
		sort.Strings(units)
		c.ExpectedUserUnits = strings.Join(units, ",")
	}
	c.AutoRemediate = c.AutoRemediate || p.AutoRemediateUserUnits
	return c
}

// SafeReadinessReason bounds untrusted agent prose before exposing it in the UI/API.
func SafeReadinessReason(s string) string {
	r := []rune(strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s))
	if len(r) > 200 {
		r = r[:200]
	}
	return string(r)
}

// UnitOK also accepts idle oneshot and static/indirect services whose last run did not fail.
func UnitOK(u UnitFact) bool {
	if !unitTrue(u.Loaded) || unitTrue(u.Masked) {
		return false
	}
	if unitTrue(u.Oneshot) {
		return u.Failed != nil && !*u.Failed
	}
	return unitTrue(u.Enabled) && unitTrue(u.Active)
}

// UnitRepairable requires explicit evidence of a safe enable or start operation.
func UnitRepairable(u UnitFact) bool {
	return unitTrue(u.Loaded) && !unitTrue(u.Masked) && !unitTrue(u.Oneshot) && !UnitOK(u) &&
		(unitTrue(u.Disabled) || (unitTrue(u.Enabled) && u.Active != nil && !*u.Active))
}
func unitTrue(v *bool) bool { return v != nil && *v }
