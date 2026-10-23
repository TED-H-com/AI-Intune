package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operatorclient"
)

func TestMachineAssignedUserCLIInputValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing required flags",
			args: []string{},
			want: "--machine, --user, and --confirm-name are required",
		},
		{
			name: "missing user",
			args: []string{"--machine", "m-123", "--confirm-name", "cnode"},
			want: "--machine, --user, and --confirm-name are required",
		},
		{
			name: "missing confirm-name",
			args: []string{"--machine", "m-123", "--user", "u-456"},
			want: "--machine, --user, and --confirm-name are required",
		},
		{
			name: "positional arguments",
			args: []string{"--machine", "m-123", "--user", "u-456", "--confirm-name", "cnode", "extra"},
			want: "positional arguments not accepted",
		},
		{
			name: "hub-url and db together",
			args: []string{"--machine", "m-123", "--user", "u-456", "--confirm-name", "cnode", "--hub-url", "http://hub.local", "--db", "/tmp/test.db"},
			want: "--hub-url and --db cannot be provided together",
		},
		{
			name: "idempotency key without expected revision",
			args: []string{"--machine", "m-123", "--user", "u-456", "--confirm-name", "cnode", "--idempotency-key", "key1"},
			want: "non-empty --idempotency-key and --expected-revision must be provided together",
		},
		{
			name: "empty idempotency key with expected revision",
			args: []string{"--machine", "m-123", "--user", "u-456", "--confirm-name", "cnode", "--idempotency-key", "", "--expected-revision", "1"},
			want: "non-empty --idempotency-key and --expected-revision must be provided together",
		},
		{
			name: "empty db path",
			args: []string{"--machine", "m-123", "--user", "u-456", "--confirm-name", "cnode", "--db", ""},
			want: "URL and database path cannot be empty",
		},
		{
			name: "empty hub-url path",
			args: []string{"--machine", "m-123", "--user", "u-456", "--confirm-name", "cnode", "--hub-url", ""},
			want: "URL and database path cannot be empty",
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
			err := runMachineAssignedUserSubcommand(t.Context(), tt.args, &out, &errOut, deps)
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
