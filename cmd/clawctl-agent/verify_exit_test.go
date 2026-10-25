package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestVerifyExit(t *testing.T) {
	if os.Getenv("CLAWCTL_VERIFY_EXIT_TEST") == "1" {
		os.Args = []string{"clawctl-agent", "verify", "--timeout=1s"}
		if os.Getenv("CLAWCTL_VERIFY_MONITOR") == "1" {
			os.Args = append(os.Args, "--monitor-only")
		}
		main()
		os.Exit(0)
	}
	for _, tc := range []struct {
		name           string
		ready, monitor bool
	}{
		{"ready", true, false}, {"monitor-only", true, true}, {"failure", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Now().UTC()
			enabled := true
			jobs := !tc.monitor
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/agent/readiness" || r.Header.Get("Authorization") != "Bearer test-token" {
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if !tc.ready {
					http.Error(w, "unavailable", http.StatusServiceUnavailable)
					return
				}
				_ = json.NewEncoder(w).Encode(model.AgentReadinessResponse{
					MachineID: "machine-1", AgentVersion: version, LastCheckinReceivedAt: &now,
					AgentStartedAt: &now, JobsEnabled: &jobs, DeviceSyncV1: &enabled,
				})
			}))
			defer server.Close()
			path := filepath.Join(t.TempDir(), "agent.json")
			digest, err := assignedSettingsDigest(120, 600)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(config{HubURL: server.URL, MachineID: "machine-1", AgentToken: "test-token",
				EnrollmentSchemaVersion: model.SchemaVersion, CheckinIntervalSeconds: 120,
				ObservationIntervalSeconds: 600, EnrollmentSettingsDigest: digest})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVerifyExit$")
			monitor := "0"
			if tc.monitor {
				monitor = "1"
			}
			cmd.Env = append(os.Environ(), "CLAWCTL_VERIFY_EXIT_TEST=1", "CLAWCTL_CONFIG="+path, "CLAWCTL_VERIFY_MONITOR="+monitor)
			out, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("verify did not exit: %s", out)
			}
			if tc.ready {
				if err != nil || !strings.HasPrefix(string(out), "Hub ready:") || !strings.HasSuffix(string(out), "\n") {
					t.Fatalf("verify success: err=%v output=%q", err, out)
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(string(out), "verification timed out") || strings.Contains(string(out), "Hub ready:") {
				t.Fatalf("verify failure: err=%v output=%q", err, out)
			}
		})
	}
}
