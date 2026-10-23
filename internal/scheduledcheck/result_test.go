package scheduledcheck

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestReasonIsBoundedSingleLineAndSanitized(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"create private script directory\nsecond line", "create private script directory"},
		{"first\rhidden", "first"},
		{"first\u2028hidden", "first"},
		{"first\u2029hidden", "first"},
		{"check failed token=synthetic-test-value", "check failed [REDACTED]"},
		{"check\x1bfailed", "check�failed"},
	} {
		if got := Reason(tc.raw); got != tc.want {
			t.Errorf("sanitized reason differs: got %q", got)
		}
	}
	got := Reason(strings.Repeat("中", 200))
	if len(got) > 240 || !utf8.ValidString(got) {
		t.Fatal("invalid bounded UTF-8")
	}
	// Credential detection precedes the display bound.
	got = Reason(strings.Repeat("x ", 110) + "token=" + strings.Repeat("synthetic", 40))
	if strings.Contains(got, "synthetic") {
		t.Fatal("credential-shaped fixture leaked")
	}
}
