package diskpolicy

import (
	"encoding/json"
	"testing"
)

func TestDiskGrowthPolicy_Valid(t *testing.T) {
	tests := []struct {
		name     string
		policy   DiskGrowthPolicy
		expected bool
	}{
		{"Valid", DiskGrowthPolicy{GBPerHour: 10, WindowMinutes: 60}, true},
		{"Valid min", DiskGrowthPolicy{GBPerHour: 1, WindowMinutes: 10}, true},
		{"Valid max", DiskGrowthPolicy{GBPerHour: 1000000, WindowMinutes: 1440}, true},
		{"Invalid GBPerHour low", DiskGrowthPolicy{GBPerHour: 0, WindowMinutes: 60}, false},
		{"Invalid GBPerHour high", DiskGrowthPolicy{GBPerHour: 1000001, WindowMinutes: 60}, false},
		{"Invalid WindowMinutes low", DiskGrowthPolicy{GBPerHour: 10, WindowMinutes: 9}, false},
		{"Invalid WindowMinutes high", DiskGrowthPolicy{GBPerHour: 10, WindowMinutes: 1441}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.Valid(); got != tt.expected {
				t.Errorf("DiskGrowthPolicy.Valid() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestDiskPolicy_Protections(t *testing.T) {
	p := DiskPolicy{
		ProtectPaths: []string{"/custom/path"},
	}
	protections := p.Protections()

	if len(protections.BuiltInNames) == 0 {
		t.Errorf("Expected BuiltInNames to be populated")
	}
	if len(protections.ProtectedClasses) == 0 {
		t.Errorf("Expected ProtectedClasses to be populated")
	}

	foundCustom := false
	for _, path := range protections.AdditivePaths {
		if path == "/custom/path" {
			foundCustom = true
			break
		}
	}
	if !foundCustom {
		t.Errorf("Expected custom path to be in AdditivePaths")
	}
}

func TestDefaultDiskPolicy(t *testing.T) {
	p := DefaultDiskPolicy()
	if p.SchemaVersion != 1 {
		t.Errorf("Expected SchemaVersion to be 1, got %d", p.SchemaVersion)
	}
	if p.QuarantineTTLDays != 7 {
		t.Errorf("Expected QuarantineTTLDays to be 7, got %d", p.QuarantineTTLDays)
	}
}

func TestCanonicalDiskPolicy(t *testing.T) {
	p := DefaultDiskPolicy()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("Failed to marshal default policy: %v", err)
	}

	parsed, canonical, digest, err := CanonicalDiskPolicy(raw)
	if err != nil {
		t.Fatalf("CanonicalDiskPolicy returned unexpected error: %v", err)
	}

	if parsed.SchemaVersion != p.SchemaVersion {
		t.Errorf("Expected SchemaVersion to be %d, got %d", p.SchemaVersion, parsed.SchemaVersion)
	}
	if len(canonical) == 0 {
		t.Errorf("Expected canonical JSON to be non-empty")
	}
	if digest == "" {
		t.Errorf("Expected digest to be non-empty")
	}
}

func TestCanonicalDiskPolicy_Errors(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{"Invalid JSON", `{"schema_version": 1`},
		{"Multiple documents", `{"schema_version": 1}{}`},
		{"Unknown fields", `{"schema_version": 1, "unknown": true}`},
		{"Invalid growth policy", `{"schema_version": 1, "growth": {"gb_per_hour": 0, "window_minutes": 60}}`},
		{"DataMounts too many", `{"schema_version": 1, "data_mounts": ["/1", "/2", "/3", "/4", "/5", "/6", "/7", "/8", "/9", "/10", "/11", "/12", "/13", "/14", "/15", "/16"]}`},
		{"DataMounts not clean", `{"schema_version": 1, "data_mounts": ["/var/tmp/../test"]}`},
		{"ProtectPaths not absolute", `{"schema_version": 1, "protect_paths": ["relative/path"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, _, err := CanonicalDiskPolicy([]byte(tt.raw))
			if err == nil {
				t.Errorf("Expected error for %s", tt.name)
			}
		})
	}
}
