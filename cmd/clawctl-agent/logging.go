package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

func consoleArgs(args []string) ([]string, bool) {
	// Global flags precede the action, preserving subcommand flag values.
	console := false
	for len(args) > 0 && args[0] == "--console" {
		console = true
		args = args[1:]
	}
	return args, console
}

func defaultAgentLogPath() (string, error) {
	dir, err := os.UserCacheDir() // LOCALAPPDATA on Windows.
	if err != nil {
		return "", err
	}
	return filepath.Abs(filepath.Join(dir, "clawctl", "logs", "agent.log"))
}

func logRecoveredPanic(value any) bool {
	if value == nil {
		return false
	}
	log.Printf("panic: %v\n%s", value, debug.Stack())
	return true
}

// rotatingLog serializes writes and closes the file before renaming (Windows).
// Raw runtime stderr uses a separate stable crash file, never this handle.
type rotatingLog struct {
	mu      sync.Mutex
	path    string
	max     int64
	backups int
	file    *os.File
}

func openRotatingLog(path string, max int64, backups int) (*rotatingLog, error) {
	r := &rotatingLog{path: path, max: max, backups: backups}
	var err error
	r.file, err = os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	return r, err
}

func (r *rotatingLog) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return 0, fmt.Errorf("log file closed")
	}
	info, err := r.file.Stat()
	if err != nil {
		return 0, err
	}
	if info.Size() > 0 && info.Size()+int64(len(p)) > r.max {
		if err := r.file.Close(); err != nil {
			return 0, err
		}
		r.file = nil
		rotateErr := r.rotate()
		r.file, err = os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return 0, err
		}
		if rotateErr != nil {
			return 0, rotateErr
		}
	}
	return r.file.Write(p)
}

func (r *rotatingLog) rotate() error {
	for i := r.backups; i >= 1; i-- {
		dst := fmt.Sprintf("%s.%d", r.path, i)
		src := r.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", r.path, i-1)
		}
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(src, dst); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func (r *rotatingLog) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.file == nil {
		return nil
	}
	err := r.file.Close()
	r.file = nil
	return err
}

// agentErrorHook preserves the existing log destination and mirrors diagnostics
// to the structured local spool. Spool failures never affect agent logging.
type agentErrorHook struct {
	output    io.Writer
	errors    *errlog.Writer
	machineID string
}

func (h *agentErrorHook) Write(p []byte) (int, error) {
	msg := strings.TrimSpace(string(p))
	if code, level := agentErrorCode(msg); code != "" {
		_ = h.errors.Write(errlog.Record{MachineID: h.machineID, Component: "intune-agent", Version: version, Level: level, Code: code, Msg: msg})
	}
	return h.output.Write(p)
}

func agentErrorCode(msg string) (string, string) {
	s := strings.ToLower(msg)
	failed := false
	for _, marker := range []string{"failed", "failure", "cannot ", "could not", "timed out", "timeout", "stalled", "stuck", "rejected", "incomplete", "abandoning", "expired", "error:", "panic:", "unexpected state", "finished as failed", "deadline exceeded", "blocked", "not started", "canceling", "canceled"} {
		if strings.Contains(s, marker) {
			failed = true
			break
		}
	}
	if !failed {
		return "", ""
	}
	switch {
	case strings.Contains(s, "observation") && (strings.Contains(s, "stall") || strings.Contains(s, "stuck") || strings.Contains(s, "deadline exceeded")):
		return "agent.observation.stalled", "warn"
	case strings.Contains(s, "upgrade") || strings.Contains(s, "update"):
		return "agent.upgrade.failed", "error"
	case strings.Contains(s, "readiness"):
		return "agent.readiness.failed", "error"
	case strings.Contains(s, "cannot send") || strings.Contains(s, "failed to fetch") || strings.Contains(s, "failed to claim") || strings.Contains(s, "failed to send"):
		return "agent.hub_call.failed", "error"
	case strings.Contains(s, "job ") || strings.Contains(s, "job runner"):
		return "agent.job.failed", "error"
	case strings.Contains(s, "observation"):
		return "agent.observation.failed", "warn"
	default:
		return "agent.runtime.failed", "error"
	}
}

func setupAgentErrorLog(cfg config) func() {
	path := os.Getenv("AI_INTUNE_ERROR_LOG")
	if path == "" {
		path = cfg.ErrorLog
	}
	w, err := errlog.NewWriter(path)
	if err != nil {
		return func() {}
	}
	previous := log.Writer()
	log.SetOutput(&agentErrorHook{output: previous, errors: w, machineID: cfg.MachineID})
	return func() { log.SetOutput(previous); _ = w.Close() }
}
