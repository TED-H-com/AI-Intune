package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/teddashh/AI-Intune/internal/errlog"
)

const errorUploadBytes = 256 << 10

type errorUploadCursor struct {
	File     string `json:"file"`
	Identity string `json:"identity"`
	Offset   int64  `json:"offset"`
	Size     int64  `json:"size"`
	Anchor   string `json:"anchor"`
}
type errorUploadState struct {
	Cursors map[string]errorUploadCursor `json:"cursors"`
	RetryAt time.Time                    `json:"retry_at,omitempty"`
}
type errorUploader struct {
	cfg       config
	paths     []string
	stateFile string
	state     errorUploadState
	now       func() time.Time
}

func newErrorUploader(cfg config, stateFile string) (*errorUploader, error) {
	u := &errorUploader{cfg: cfg, paths: errorUploadPaths(cfg), stateFile: stateFile, now: time.Now}
	b, err := os.ReadFile(stateFile)
	if err == nil {
		err = json.Unmarshal(b, &u.state)
	}
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if u.state.Cursors == nil {
		u.state.Cursors = make(map[string]errorUploadCursor)
	}
	return u, nil
}

func errorUploadPaths(cfg config) []string {
	agent := os.Getenv("AI_INTUNE_ERROR_LOG")
	if agent == "" {
		agent = cfg.ErrorLog
	}
	if agent == "" {
		agent = errlog.DefaultPath()
	}
	paths := []string{agent}
	bat := cfg.BATErrorLogs
	if value, ok := os.LookupEnv("AI_INTUNE_BAT_ERROR_LOGS"); ok {
		bat = strings.Split(value, ",")
	}
	if bat == nil {
		if runtime.GOOS == "windows" {
			if root := os.Getenv("LOCALAPPDATA"); root != "" {
				bat = append(bat, filepath.Join(root, "BAT", "logs", "errors.jsonl"))
			}
		} else {
			if len(cfg.BATUsers) == 0 {
				if home, e := os.UserHomeDir(); e == nil {
					bat = append(bat, filepath.Join(home, ".bat", "logs", "errors.jsonl"))
				}
			}
			for _, name := range cfg.BATUsers {
				if account, e := user.Lookup(name); e == nil {
					bat = append(bat, filepath.Join(account.HomeDir, ".bat", "logs", "errors.jsonl"))
				}
			}
		}
	}
	seen := map[string]bool{agent: true}
	for _, path := range bat {
		path = strings.TrimSpace(path)
		if path != "" && !seen[path] {
			paths = append(paths, path)
			seen[path] = true
		}
	}
	return paths
}

func runErrorUploads(ctx context.Context, cfg config) {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("AI_INTUNE_ERROR_UPLOAD")), "off") {
		return
	}
	u, err := newErrorUploader(cfg, filepath.Join(filepath.Dir(statePath()), "error-upload-cursor.json"))
	if err != nil {
		return
	}
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for {
		_ = u.upload(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (u *errorUploader) save() error {
	b, err := json.Marshal(u.state)
	if err != nil {
		return err
	}
	return writePrivateFile(u.stateFile, b)
}

func errorAnchor(f *os.File, offset int64) string {
	b := make([]byte, min(offset, 64))
	if _, err := f.ReadAt(b, offset-int64(len(b))); err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (u *errorUploader) upload(ctx context.Context) error {
	if u.now().Before(u.state.RetryAt) {
		return nil
	}
	// Bound work per pass as well as batch memory. Remaining data resumes next tick.
	budget := 100
	// Prune before reading so a continuously busy spool cannot grow cursor state.
	live := map[string]bool{}
	for _, base := range u.paths {
		for rotation := 5; rotation >= 0; rotation-- {
			path := base
			if rotation > 0 {
				path = fmt.Sprintf("%s.%d", base, rotation)
			}
			f, err := os.Open(path)
			if err != nil {
				continue
			}
			info, err := f.Stat()
			if err == nil && info.Mode().IsRegular() {
				if identity, e := errorFileIdentity(f, info); e == nil {
					live[base+"|"+identity] = true
				}
			}
			f.Close()
		}
	}
	for key := range u.state.Cursors {
		if !live[key] {
			delete(u.state.Cursors, key)
		}
	}
	for _, base := range u.paths {
		// The shared writer retains the active file plus four numbered rotations.
		for rotation := 5; rotation >= 0; rotation-- {
			path := base
			if rotation > 0 {
				path = fmt.Sprintf("%s.%d", base, rotation)
			}
			f, err := os.Open(path)
			if os.IsNotExist(err) {
				continue
			}
			if err != nil {
				continue
			}
			info, err := f.Stat()
			if err != nil || !info.Mode().IsRegular() {
				f.Close()
				continue
			}
			identity, err := errorFileIdentity(f, info)
			if err != nil {
				f.Close()
				return err
			}
			key := base + "|" + identity
			cursor := u.state.Cursors[key]
			if cursor.Identity != identity || info.Size() < cursor.Size || cursor.Offset > info.Size() || (cursor.Offset > 0 && cursor.Anchor != errorAnchor(f, cursor.Offset)) {
				cursor = errorUploadCursor{}
			}
			cursor.File = path
			cursor.Identity = identity
			cursor.Size = info.Size()
			err = u.uploadFile(ctx, f, key, cursor, &budget)
			f.Close()
			if err != nil {
				return err
			}
			if budget == 0 {
				return nil
			}
		}
	}
	return u.save()
}

func (u *errorUploader) uploadFile(ctx context.Context, f *os.File, key string, cursor errorUploadCursor, budget *int) error {
	if _, err := f.Seek(cursor.Offset, io.SeekStart); err != nil {
		return err
	}
	reader := bufio.NewReaderSize(f, 32<<10)
	batch := make([]json.RawMessage, 0, 200)
	size := 2
	offset := cursor.Offset
	flush := func() error {
		anchor := errorAnchor(f, offset)
		if len(batch) > 0 {
			endpoint := strings.TrimRight(u.cfg.HubURL, "/") + "/api/v1/machines/" + url.PathEscape(u.cfg.MachineID) + "/errors"
			status, err := doJSONStatus(withHubRetryInterval(ctx, time.Minute), http.MethodPost, endpoint, u.cfg.AgentToken, batch, nil)
			if status == http.StatusNotFound {
				u.state.RetryAt = u.now().Add(time.Hour)
				if e := u.save(); e != nil {
					return e
				}
				return err
			}
			if err != nil {
				return err
			}
			*budget--
		}
		cursor.Offset = offset
		cursor.Anchor = anchor
		u.state.Cursors[key] = cursor
		if err := u.save(); err != nil {
			return err
		}
		batch = batch[:0]
		size = 2
		return nil
	}
	// ReadSlice bounds allocations even for corrupt or oversized source lines.
	var line []byte
	consumed := int64(0)
	oversized := false
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		fragment, err := reader.ReadSlice('\n')
		consumed += int64(len(fragment))
		if !oversized {
			if len(line)+len(fragment) > errorUploadBytes {
				oversized = true
				line = nil
			} else {
				line = append(line, fragment...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if err == io.EOF {
				return flush()
			}
			return err
		}
		var record errlog.Record
		var raw []byte
		if !oversized && json.Unmarshal(line, &record) == nil {
			if record.Count == 0 {
				record.Count = 1
			}
			record.MachineID = u.cfg.MachineID
			b, _ := json.Marshal(record)
			var value any
			_ = json.Unmarshal(b, &value)
			raw, _ = json.Marshal(redactUploadValue(value))
			record = errlog.Record{}
			if json.Unmarshal(raw, &record) != nil || record.TS.IsZero() || record.Component == "" || record.Code == "" || record.Count < 1 || record.Count > 1000000 || (record.Level != "warn" && record.Level != "error") {
				raw = nil
			} else {
				record.Fingerprint = errlog.Fingerprint(record.Component, record.Code, record.Msg)
				raw, _ = json.Marshal(record)
				if errlog.ContainsSecret(string(raw)) || len(raw)+2 > errorUploadBytes {
					raw = nil
				}
			}
		}
		extra := len(raw)
		if len(batch) > 0 {
			extra++
		}
		if len(raw) > 0 && (len(batch) == 200 || size+extra > errorUploadBytes) {
			if err := flush(); err != nil {
				return err
			}
			if *budget == 0 {
				return nil
			}
		}
		offset += consumed
		if len(raw) > 0 {
			if len(batch) > 0 {
				size++
			}
			batch = append(batch, json.RawMessage(raw))
			size += len(raw)
		}
		consumed = 0
		line = nil
		oversized = false
	}
}

func redactUploadValue(value any) any {
	switch v := value.(type) {
	case string:
		return errlog.Redact(v)
	case []any:
		for i := range v {
			v[i] = redactUploadValue(v[i])
		}
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, x := range v {
			if errlog.ContainsSecret(k + "=credential") {
				out["[REDACTED]"] = "[REDACTED]"
			} else {
				out[errlog.Redact(k)] = redactUploadValue(x)
			}
		}
		return out
	}
	return value
}
