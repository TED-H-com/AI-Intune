package boundedtext

import (
	"strings"
	"testing"
)

func TestReason(t *testing.T) {
	for _, s := range []string{"collect facts", "rotate disk on node1, per ticket #42", "node1.example.com: inspect /var, then retry!", "中文：清理磁碟，工單 #42", "Réparer le disque — déjà approuvé", "restart 123 machines (approved)", strings.Repeat("中", 500), "  trim surrounding whitespace  ", "password rotation approved", "token expired; investigate"} {
		got, err := Reason(s)
		if err != nil || got != strings.TrimSpace(s) {
			t.Errorf("valid prose rejected: %v", err)
		}
	}
	for _, tt := range []struct{ in, rule string }{{" \t", "empty"}, {strings.Repeat("中", 612), "612 characters; maximum is 500"}, {"hello\nworld", "control character"}, {"a\x00b", "control character"}, {"token=synthetic", "assignment"}, {"password: synthetic", "assignment"}, {"Bearer abcdefgh12345678", "bearer token"}, {"-----BEGIN PRIVATE KEY-----", "PEM block"}, {"ghp_abcdefghijklmnopqrstuvwxyz", "known token prefix"}, {"aB3dE6gH9jK2mN5pQ8sT1vW4xY7zC0fL", "key-like"}} {
		_, err := Reason(tt.in)
		if err == nil || !strings.Contains(err.Error(), tt.rule) {
			t.Errorf("expected %s, got %v", tt.rule, err)
		}
	}
}
