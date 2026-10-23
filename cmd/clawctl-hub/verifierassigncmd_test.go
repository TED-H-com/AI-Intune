package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorclient"
)

func TestVerifierAssignCLIInputValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing verifier id",
			args: []string{},
			want: "verifier assign: must provide a verifier-id",
		},
		{
			name: "invalid verifier id with slash",
			args: []string{"--job", "job-123", "verifier/id"},
			want: "verifier-id cannot be empty, contain leading/trailing whitespace, dot segments, or slashes",
		},
		{
			name: "missing job id",
			args: []string{"v-123"},
			want: "--job cannot be empty",
		},
		{
			name: "job id with slash",
			args: []string{"--job", "job/123", "v-123"},
			want: "verifier assign: --job cannot contain slashes or dot segments",
		},
		{
			name: "job id with dot segment",
			args: []string{"--job", ".", "v-123"},
			want: "verifier assign: --job cannot contain slashes or dot segments",
		},
		{
			name: "preview with reason",
			args: []string{"--job", "job-123", "--preview", "--reason", "test-reason", "v-123"},
			want: "--preview creates no writes and does not accept --reason",
		},
		{
			name: "preview with confirm-name",
			args: []string{"--job", "job-123", "--preview", "--confirm-name", "verifier-name", "v-123"},
			want: "--preview creates no writes and does not accept --confirm-name",
		},
		{
			name: "apply missing reason",
			args: []string{"--job", "job-123", "--confirm-name", "vname", "v-123"},
			want: "--reason cannot be empty",
		},
		{
			name: "apply missing confirm-name",
			args: []string{"--job", "job-123", "--reason", "rname", "v-123"},
			want: "--confirm-name cannot be empty",
		},
		{
			name: "apply with json output",
			args: []string{"--job", "job-123", "--reason", "rname", "--confirm-name", "vname", "--json", "v-123"},
			want: "verifier assign: --json is only for --preview",
		},
		{
			name: "hub-url and db together",
			args: []string{"--job", "job-123", "--hub-url", "http://hub.local", "--db", "/tmp/test.db", "v-123"},
			want: "--hub-url (HTTP mode) and --db (direct mode) cannot both be specified",
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
			err := runVerifierAssign(t.Context(), tt.args, &out, &errOut, deps)
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
