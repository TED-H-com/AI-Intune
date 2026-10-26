package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestExecutionReadinessCheckins(t *testing.T) {
	if os.Getenv("CLAWCTL_TEST_EXECUTION_CHECKINS") == "1" {
		os.Args = []string{"clawctl-agent"}
		main()
		return
	}
	for _, tc := range []struct {
		name   string
		policy *model.ExecutionPolicy
		jobs   bool
	}{
		{"managed", &model.ExecutionPolicy{Mode: model.ExecutionManaged, Revision: 1}, true},
		{"monitor-only", &model.ExecutionPolicy{Mode: model.ExecutionMonitorOnly, Revision: 2}, false},
		{"missing-policy", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			checkins := make(chan model.Checkin, 8)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/checkins" {
					http.NotFound(w, r)
					return
				}
				var hb model.Checkin
				if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
					http.Error(w, "invalid check-in", http.StatusBadRequest)
					return
				}
				select {
				case checkins <- hb:
				default:
				}
				_ = json.NewEncoder(w).Encode(model.CheckinResponse{ExecutionPolicy: tc.policy})
			}))
			defer server.Close()
			home := t.TempDir()
			path := filepath.Join(home, ".config", "clawctl", "agent.json")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			digest, err := assignedSettingsDigest(120, 600)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(config{HubURL: server.URL, MachineID: "machine-1", AgentToken: "test-token",
				JobsEnabled: true, EnrollmentSchemaVersion: model.SchemaVersion, CheckinIntervalSeconds: 120,
				ObservationIntervalSeconds: 600, EnrollmentSettingsDigest: digest})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutionReadinessCheckins$")
			cmd.Env = append(os.Environ(), "CLAWCTL_TEST_EXECUTION_CHECKINS=1", "HOME="+home,
				"XDG_CONFIG_HOME="+filepath.Join(home, ".config"), "XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
				"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"), "XDG_RUNTIME_DIR="+home,
				"CLAWCTL_CONFIG="+path, "PATH="+home)
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = cmd.Wait() }()
			next := func() model.Checkin {
				t.Helper()
				select {
				case hb := <-checkins:
					return hb
				case <-time.After(5 * time.Second):
					t.Fatal("execution state was not reported promptly")
					return model.Checkin{}
				}
			}
			first := next()
			if first.JobsEnabled == nil || *first.JobsEnabled {
				t.Fatal("startup advertised jobs before accepting a Hub policy")
			}
			if tc.policy != nil {
				second := next()
				if second.JobsEnabled == nil || *second.JobsEnabled != tc.jobs || second.ExecutionPolicy == nil || *second.ExecutionPolicy != *tc.policy {
					t.Fatalf("confirmed state does not match accepted policy: jobs=%v policy=%+v", second.JobsEnabled, second.ExecutionPolicy)
				}
			}
			select {
			case hb := <-checkins:
				t.Fatalf("unchanged or rejected policy caused an extra check-in: %+v", hb.ExecutionPolicy)
			case <-time.After(2 * time.Second):
			}
		})
	}
}
