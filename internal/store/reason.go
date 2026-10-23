package store

import "github.com/teddashh/AI-Intune/internal/boundedtext"

func validAuditReason(reason string) bool {
	_, err := boundedtext.Reason(reason)
	return err == nil
}

// Audit explanations are bounded in characters, independently of byte-bounded
// machine identifiers and internal audit details.
func truncReason(reason string) string {
	runes := []rune(reason)
	if len(runes) > boundedtext.MaxReasonRunes {
		return string(runes[:boundedtext.MaxReasonRunes])
	}
	return reason
}
