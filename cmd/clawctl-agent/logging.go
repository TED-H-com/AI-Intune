package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"sync"
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
