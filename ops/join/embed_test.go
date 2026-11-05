package join

import (
	"strings"
	"testing"
)

func TestEmbeddedScripts(t *testing.T) {
	if len(Script) == 0 {
		t.Error("Expected Script (join.sh) to be non-empty")
	}
	if !strings.HasPrefix(Script, "#!") {
		t.Errorf("Expected Script to start with shebang, got %q", Script[:10])
	}

	if len(PowerShell) == 0 {
		t.Error("Expected PowerShell (join.ps1) to be non-empty")
	}
	if !strings.Contains(PowerShell, "param") {
		t.Errorf("Expected PowerShell script to contain 'param'")
	}
}
