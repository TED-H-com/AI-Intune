package errlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

// DefaultPath returns the agent's system-wide error log location.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		root := os.Getenv("ProgramData")
		if root == "" {
			root = `C:\ProgramData`
		}
		return filepath.Join(root, "AI-Intune", "logs", "errors.jsonl")
	}
	return "/var/log/ai-intune/errors.jsonl"
}

// Writer serializes redacted records and retains five files including the active
// file. Records are buffered for a fixed 60-second window per fingerprint.
// Write and Close return I/O errors; background flush errors are returned by Close.
type Writer struct {
	mu      sync.Mutex
	path    string
	file    *os.File
	max     int64
	window  time.Duration
	pending map[string]Record
	timers  map[string]*time.Timer
	closed  bool
	err     error
}

func NewWriter(path string) (*Writer, error) {
	if path == "" {
		path = DefaultPath()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	return &Writer{path: path, file: f, max: 10 * 1024 * 1024, window: 60 * time.Second, pending: make(map[string]Record), timers: make(map[string]*time.Timer)}, nil
}

// Write copies and redacts the entire JSON representation, including nested
// context and metadata, before retaining it. Fingerprints are always recomputed.
func (w *Writer) Write(r Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	var fields any
	if err = json.Unmarshal(b, &fields); err != nil {
		return err
	}
	b, err = json.Marshal(redactValue(fields))
	if err != nil {
		return err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return err
	}
	r.Fingerprint = Fingerprint(r.Component, r.Code, r.Msg)
	if r.TS.IsZero() {
		r.TS = time.Now().UTC()
	}
	if r.Count < 1 {
		r.Count = 1
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return os.ErrClosed
	}
	key := r.Fingerprint
	if old, ok := w.pending[key]; ok {
		old.Count += r.Count
		w.pending[key] = old
		return nil
	}
	w.pending[key] = r
	w.timers[key] = time.AfterFunc(w.window, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		if !w.closed {
			w.err = errors.Join(w.err, w.flush(key))
		}
	})
	return nil
}

func redactValue(v any) any {
	switch x := v.(type) {
	case string:
		return Redact(x)
	case []any:
		for i := range x {
			x[i] = redactValue(x[i])
		}
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, val := range x {
			// Sensitive context keys must also cover unlabelled credential values.
			if ContainsSecret(k + "=value") {
				out[Redact(k)] = redacted
			} else {
				out[Redact(k)] = redactValue(val)
			}
		}
		return out
	}
	return v
}

func (w *Writer) flush(key string) error {
	r, ok := w.pending[key]
	if !ok {
		return nil
	}
	delete(w.pending, key)
	if timer := w.timers[key]; timer != nil {
		timer.Stop()
	}
	delete(w.timers, key)
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if w.file == nil {
		return os.ErrClosed
	}
	info, err := w.file.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 0 && info.Size()+int64(len(b)) > w.max {
		if err := w.file.Close(); err != nil {
			return err
		}
		rotateErr := w.rotate()
		w.file, err = os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.Join(rotateErr, err)
		}
		if rotateErr != nil {
			return rotateErr
		}
	}
	_, err = w.file.Write(b)
	return err
}

func (w *Writer) rotate() error {
	for i := 4; i >= 1; i-- {
		dst := fmt.Sprintf("%s.%d", w.path, i)
		src := w.path
		if i > 1 {
			src = fmt.Sprintf("%s.%d", w.path, i-1)
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

func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return w.err
	}
	w.closed = true
	for _, timer := range w.timers {
		timer.Stop()
	}
	for key := range w.pending {
		w.err = errors.Join(w.err, w.flush(key))
	}
	if w.file != nil {
		w.err = errors.Join(w.err, w.file.Close())
	}
	return w.err
}
