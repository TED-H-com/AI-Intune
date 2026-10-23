package main

import (
	"testing"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestParseUsageToolCallLimit(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want int
	}{{"", store.DefaultUsageToolCallLimit}, {"2", 2}, {"2000", 2000}} {
		got, err := parseUsageToolCallLimit(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("%q: got %d, %v", tc.raw, got, err)
		}
	}
	for _, raw := range []string{"0", "-1", "abc", "99999999999999999999999"} {
		if _, err := parseUsageToolCallLimit(raw); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
}
