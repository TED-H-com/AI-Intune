package main

import (
	"bytes"
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

func TestLogRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	r, err := openRotatingLog(path, 5, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for _, line := range []string{"0000\n", "1111\n", "2222\n", "3333\n", "4444\n", "5555\n", "6666\n"} {
		if n, err := r.Write([]byte(line)); err != nil || n != len(line) {
			t.Fatalf("write: %d, %v", n, err)
		}
	}
	for i, name := range []string{"agent.log", "agent.log.1", "agent.log.2", "agent.log.3", "agent.log.4", "agent.log.5"} {
		data, err := os.ReadFile(filepath.Join(filepath.Dir(path), name))
		if err != nil {
			t.Fatal(err)
		}
		want := strings.Repeat(string(rune('6'-i)), 4) + "\n"
		if string(data) != want {
			t.Errorf("%s = %q, want %q", name, data, want)
		}
	}
	if _, err := os.Stat(path + ".6"); !os.IsNotExist(err) {
		t.Fatalf("unexpected sixth backup: %v", err)
	}
}

func TestRecoveredPanicWritesLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.log")
	r, err := openRotatingLog(path, 4096, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	previous := log.Writer()
	log.SetOutput(r)
	defer log.SetOutput(previous)
	func() {
		defer func() {
			if !logRecoveredPanic(recover()) {
				t.Error("panic not recovered")
			}
		}()
		panic("test panic marker")
	}()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "panic: test panic marker") || !strings.Contains(string(data), "logging_test.go") {
		t.Fatalf("missing panic/stack: %s", data)
	}
}

func TestConsoleGlobalDispatch(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		action  string
		console bool
	}{
		{[]string{"--console"}, actAgent, true},
		{[]string{"--console", "version"}, actVersion, true},
		{[]string{"--console", "--wat"}, actUnknown, true},
		{[]string{"log-path"}, actLogPath, false},
	} {
		args, console := consoleArgs(tc.args)
		if console != tc.console || dispatch(args) != tc.action {
			t.Fatalf("%q: %q, %v", tc.args, dispatch(args), console)
		}
	}
}

func TestAgentErrorLogHook(t *testing.T) {
	path := filepath.Join(t.TempDir(), "errors.jsonl")
	t.Setenv("AI_INTUNE_ERROR_LOG", path)
	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	defer log.SetOutput(previous)
	closeLog := setupAgentErrorLog(config{MachineID: "machine-test", ErrorLog: filepath.Join(t.TempDir(), "ignored.jsonl")})
	for _, msg := range []string{"cannot send check-in (will retry): token=secret-value", "job abc complete failed: denied", "upgrade failed: denied", "readiness failed: denied", "observation stalled", "applied new settings"} {
		log.Print(msg)
	}
	closeLog()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("records = %d", len(lines))
	}
	codes := map[string]bool{}
	for _, line := range lines {
		var r errlog.Record
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatal(err)
		}
		if r.MachineID != "machine-test" || r.Component != "intune-agent" {
			t.Fatalf("metadata: %+v", r)
		}
		codes[r.Code] = true
	}
	for _, code := range []string{"agent.hub_call.failed", "agent.job.failed", "agent.upgrade.failed", "agent.readiness.failed", "agent.observation.stalled"} {
		if !codes[code] {
			t.Errorf("missing %s", code)
		}
	}
	if strings.Contains(string(data), "secret-value") {
		t.Fatal("unredacted spool")
	}
	if !strings.Contains(output.String(), "applied new settings") {
		t.Fatal("existing output lost")
	}
}

func TestAgentErrorLogOpenFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AI_INTUNE_ERROR_LOG", filepath.Join(path, "errors.jsonl"))
	previous := log.Writer()
	closeLog := setupAgentErrorLog(config{})
	defer closeLog()
	if log.Writer() != previous {
		t.Fatal("failed open changed logger")
	}
}
