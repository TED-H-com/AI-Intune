package main

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/operator"
	"github.com/teddashh/AI-Intune/internal/operatorclient"
)

func TestMachineTimelineCLIInputValidation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "missing machine",
			args: []string{},
			want: "machine timeline: --machine is required",
		},
		{
			name: "positional arguments",
			args: []string{"--machine", "m-123", "extra-arg"},
			want: "machine timeline: positional arguments not accepted",
		},
		{
			name: "json and csv together",
			args: []string{"--machine", "m-123", "--json", "--csv"},
			want: "machine timeline: --json and --csv cannot be used together",
		},
		{
			name: "days less than 1",
			args: []string{"--machine", "m-123", "--days", "0"},
			want: fmt.Sprintf("machine timeline: --days must be between 1 and %d", operator.MaxMachineTimelineDays),
		},
		{
			name: "days greater than max",
			args: []string{"--machine", "m-123", "--days", fmt.Sprintf("%d", operator.MaxMachineTimelineDays+1)},
			want: fmt.Sprintf("machine timeline: --days must be between 1 and %d", operator.MaxMachineTimelineDays),
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
			err := runMachineTimelineSubcommand(t.Context(), tt.args, &out, &errOut, deps)
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
