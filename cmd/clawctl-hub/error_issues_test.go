package main

import (
	"context"
	"testing"
)

func TestErrorIssueJobOff(t *testing.T) {
	t.Setenv("ERROR_ISSUES_ENABLED", "")
	t.Setenv("ERROR_ISSUES_TOKEN_FILE", "/missing")
	h := &hub{}
	// No store or token is needed and no goroutine may dereference the nil store.
	if err := h.startErrorIssues(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestErrorIssueJobRejectsMissingToken(t *testing.T) {
	t.Setenv("ERROR_ISSUES_ENABLED", "true")
	t.Setenv("ERROR_ISSUES_DRY_RUN", "")
	t.Setenv("ERROR_ISSUES_TOKEN_FILE", "/missing")
	h := &hub{}
	if err := h.startErrorIssues(context.Background()); err == nil {
		t.Fatal("missing token accepted")
	}
}
