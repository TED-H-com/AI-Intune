package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorclient"
)

func TestMachineNotesCLIInputValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing machine and set",
			args: []string{},
			want: "--machine and --set are required",
		},
		{
			name: "missing set",
			args: []string{"--machine", "m-123"},
			want: "--machine and --set are required",
		},
		{
			name: "missing machine",
			args: []string{"--set", "some notes"},
			want: "--machine and --set are required",
		},
		{
			name: "positional arguments",
			args: []string{"--machine", "m-123", "--set", "notes", "extra-arg"},
			want: "positional arguments not accepted",
		},
		{
			name: "preview with reason",
			args: []string{"--machine", "m-123", "--set", "notes", "--preview", "--reason", "test"},
			want: "--preview does not accept apply-only reason, confirm, or replay arguments",
		},
		{
			name: "preview with confirm-name",
			args: []string{"--machine", "m-123", "--set", "notes", "--preview", "--confirm-name", "m1"},
			want: "--preview does not accept apply-only reason, confirm, or replay arguments",
		},
		{
			name: "preview with idempotency key",
			args: []string{"--machine", "m-123", "--set", "notes", "--preview", "--idempotency-key", "key1"},
			want: "--preview does not accept apply-only reason, confirm, or replay arguments",
		},
		{
			name: "apply missing reason and confirm-name",
			args: []string{"--machine", "m-123", "--set", "notes"},
			want: "--reason and --confirm-name are required when applying",
		},
		{
			name: "apply missing confirm-name",
			args: []string{"--machine", "m-123", "--set", "notes", "--reason", "test"},
			want: "--reason and --confirm-name are required when applying",
		},
		{
			name: "apply missing reason",
			args: []string{"--machine", "m-123", "--set", "notes", "--confirm-name", "m1"},
			want: "--reason and --confirm-name are required when applying",
		},
		{
			name: "idempotency key without preview digest",
			args: []string{"--machine", "m-123", "--set", "notes", "--reason", "r", "--confirm-name", "m", "--idempotency-key", "k1"},
			want: "--idempotency-key and --preview-digest must be provided together",
		},
		{
			name: "preview digest without idempotency key",
			args: []string{"--machine", "m-123", "--set", "notes", "--reason", "r", "--confirm-name", "m", "--preview-digest", "sha256:123"},
			want: "--idempotency-key and --preview-digest must be provided together",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps := machineCommandDeps{
				discoverHubURL: func() (string, error) {
					t.Fatal("invalid inputs reached discovery")
					return "", nil
				},
				newOperatorClient: func(string) (*operatorclient.Client, error) {
					t.Fatal("invalid inputs constructed client")
					return nil, nil
				},
			}
			var out, errOut bytes.Buffer
			err := runMachineNotesSubcommand(t.Context(), tt.args, &out, &errOut, deps)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.want)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error %q does not contain expected %q", err.Error(), tt.want)
			}
			if out.Len() != 0 {
				t.Fatalf("expected empty stdout, got %q", out.String())
			}
		})
	}
}
