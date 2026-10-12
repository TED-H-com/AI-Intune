package operator

import (
	"github.com/teddashh/AI-Intune/internal/boundedtext"
)

const (
	boundedTextIssueInvalidUTF8             = "invalid_utf8"
	boundedTextIssueControlOrFormatReplaced = "control_or_format_replaced"
	boundedTextIssueTruncated               = "truncated"
)

type boundedTextPolicy uint8

const (
	boundedTextStrict boundedTextPolicy = iota
	boundedTextBlock
)

// scrubBoundedText applies the shared operator disclosure text policy. The
// returned issues are always non-nil, sorted, and unique.
func scrubBoundedText(value string, maxBytes int) (string, bool, []string) {
	return boundedtext.Scrub(value, maxBytes)
}
func scrubBoundedBlockText(value string, maxBytes int) (string, bool, []string) {
	return boundedtext.ScrubBlock(value, maxBytes)
}
func truncateBoundedUTF8(value string, maxBytes int) string {
	return boundedtext.TruncateUTF8(value, maxBytes)
}
