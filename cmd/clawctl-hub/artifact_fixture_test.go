package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/teddashh/AI-Intune/internal/artifact"
)

type artifactSidecar = artifact.Sidecar

// writeArtifactSidecar puts the sidecar of record into dir for a test fixture:
// compact JSON without HTML escaping, written to a temporary file and renamed
// to <sha256>.json.
func writeArtifactSidecar(dir string, record artifactSidecar) error {
	// 不做 HTML 轉義：sidecar 是人會 cat 來看的檔，engines 的 ">=22.19.0" 要是原文。
	b, err := marshalCompactNoEscape(record)
	if err != nil {
		return fmt.Errorf("encode artifact sidecar: %w", err)
	}
	b = append(b, '\n')
	tmp, err := os.CreateTemp(dir, ".sidecar-*.tmp")
	if err != nil {
		return fmt.Errorf("create sidecar temporary file: %w", err)
	}
	tmpPath := tmp.Name()
	keep := false
	defer func() {
		_ = tmp.Close()
		if !keep {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		return fmt.Errorf("write artifact sidecar: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync artifact sidecar: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close artifact sidecar: %w", err)
	}
	if err := os.Rename(tmpPath, filepath.Join(dir, record.SHA256+".json")); err != nil {
		return fmt.Errorf("place artifact sidecar: %w", err)
	}
	keep = true
	return nil
}

// marshalCompactNoEscape encodes v without HTML escaping, so values such as
// ">=22.19.0" stay as written.
func marshalCompactNoEscape(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}
