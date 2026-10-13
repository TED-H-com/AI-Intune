//go:build linux

package scriptcatalog

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type output struct {
	buf    bytes.Buffer
	digest hash.Hash
	cap    int
	count  int64
}

func (w *output) Write(p []byte) (int, error) {
	n := len(p)
	_, _ = w.digest.Write(p)
	w.count += int64(n)
	remaining := w.cap - w.buf.Len()
	if remaining > 0 {
		if remaining > n {
			remaining = n
		}
		_, _ = w.buf.Write(p[:remaining])
	}
	return n, nil
}
func (w *output) text() string {
	s := w.buf.String()
	if w.count > int64(w.cap) {
		// A token crossing the cap must never escape as an unrecognized fragment.
		if i := strings.LastIndexAny(s, "\n\r\t "); i >= 0 {
			s = s[:i+1]
		} else {
			s = ""
		}
	}
	s = Redact(s)
	if len(s) > w.cap {
		s = s[:w.cap]
	}
	return strings.ToValidUTF8(s, "")
}

// Run never accepts a command or path from a job. The interpreter and script
// path are fixed, and JSON args travel exclusively on stdin.
func Run(ctx context.Context, e Entry, args []byte, timeout int) (Result, error) {
	return RunPolicy(ctx, e, args, timeout, nil)
}

// RunPolicy accepts only a digest-pinned closed policy for disk entries.
func RunPolicy(ctx context.Context, e Entry, args []byte, timeout int, policy json.RawMessage) (Result, error) {
	return runPolicy(ctx, e, args, timeout, policy, nil, nil)
}

// RunReport delivers private typed output only to the supervisor, never evidence.
func RunReport(ctx context.Context, e Entry, args []byte, timeout int, policy json.RawMessage, sink io.Writer) (Result, error) {
	if e.ID != "disk-deep-report-v1" {
		return Result{}, fmt.Errorf("not a report script")
	}
	return runPolicy(ctx, e, args, timeout, policy, sink, nil)
}

// RunDiskAction is the sole execution entry point for the signed action helpers.
func RunDiskAction(ctx context.Context, e Entry, args []byte, timeout int, action DiskActionRun) (Result, error) {
	if !IsDiskAction(e.ID) || action.Renew == nil || len(action.Authorization) == 0 || len(action.Authorization) > 3<<20 || action.JobID == "" || action.MachineID == "" {
		return Result{}, fmt.Errorf("signed disk action authority required")
	}
	return runPolicy(ctx, e, args, timeout, nil, action.Sink, &action)
}

// createPrivateScriptDir prefers the cache allowed by the agent system unit's
// ReadWritePaths, since its default temporary directory can be read-only.
func createPrivateScriptDir() (string, error) {
	if home, err := os.UserHomeDir(); err == nil {
		parent := filepath.Join(home, ".cache", "clawctl", "scripts")
		if err := os.MkdirAll(parent, 0700); err == nil {
			if dir, err := os.MkdirTemp(parent, "clawctl-script-*"); err == nil {
				return dir, nil
			}
		}
	}
	return os.MkdirTemp(os.TempDir(), "clawctl-script-*")
}

func runPolicy(ctx context.Context, e Entry, args []byte, timeout int, policy json.RawMessage, sink io.Writer, action *DiskActionRun) (Result, error) {
	var result Result
	if os.Geteuid() == 0 || e.RunsAs != "agent-user" || !e.AllowsOS("linux") || timeout < 1 || timeout > e.MaxTimeout || e.OutputCap < 1 || e.OutputCap > 64<<10 || Digest(e.Bytes) != e.SHA256 {
		return result, fmt.Errorf("invalid catalog execution constraints")
	}
	canonical, err := e.Validate(args)
	if err != nil {
		return result, err
	}
	if IsDiskAction(e.ID) {
		if action == nil {
			return result, fmt.Errorf("disk action requires signed job authority")
		}
		canonical, err = json.Marshal(struct {
			Args          json.RawMessage `json:"args"`
			Canonical     string          `json:"canonical_args"`
			MachineID     string          `json:"machine_id"`
			JobID         string          `json:"job_id"`
			Authorization json.RawMessage `json:"authorization"`
		}{canonical, string(canonical), action.MachineID, action.JobID, action.Authorization})
		if err != nil {
			return result, fmt.Errorf("invalid action envelope")
		}
	} else if IsDisk(e.ID) {
		var a struct {
			PolicyDigest string `json:"policy_digest"`
		}
		_ = json.Unmarshal(canonical, &a)
		if len(policy) == 0 || len(policy) > 32768 || "sha256:"+Digest(policy) != a.PolicyDigest {
			return result, fmt.Errorf("disk policy digest mismatch")
		}
		canonical, _ = json.Marshal(struct {
			Args   json.RawMessage `json:"args"`
			Policy json.RawMessage `json:"policy"`
		}{canonical, policy})
	} else if len(policy) > 0 {
		return result, fmt.Errorf("policy only allowed for disk scripts")
	}
	dir, err := createPrivateScriptDir()
	if err != nil {
		return result, fmt.Errorf("create private script directory")
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "script.sh")
	if os.WriteFile(path, e.Bytes, 0600) != nil {
		return result, fmt.Errorf("write embedded script")
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
	defer cancel()
	interpreter := "/bin/sh"
	home := dir
	if e.ID == "bat-sweep-report-v1" || IsDisk(e.ID) {
		interpreter = "/usr/bin/python3"
		account, err := user.Current()
		if err != nil || account.HomeDir == "" {
			return result, fmt.Errorf("resolve agent user home")
		}
		home = account.HomeDir
	}
	argv := []string{path}
	if e.ID == "bat-sweep-report-v1" || IsDisk(e.ID) {
		argv = []string{"-I", "-S", "-B", path}
	}
	cmd := exec.CommandContext(ctx, interpreter, argv...)
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "HOME=" + home, "TMPDIR=" + dir, "PYTHONDONTWRITEBYTECODE=1"}
	cmd.Stdin = bytes.NewReader(canonical)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	cmd.WaitDelay = time.Second
	stdout := output{digest: sha256.New(), cap: e.OutputCap}
	if action != nil {
		stdout.cap = 256 << 10
	}
	stderr := output{digest: sha256.New(), cap: e.OutputCap}
	cmd.Stdout = &stdout
	if sink != nil {
		cmd.Stdout = io.MultiWriter(&stdout, sink)
	}
	cmd.Stderr = &stderr
	var grantR, grantW, requestR, requestW *os.File
	var renewalDone chan struct{}
	if action != nil {
		grantR, grantW, err = os.Pipe()
		if err != nil {
			return result, err
		}
		defer grantR.Close()
		defer grantW.Close()
		requestR, requestW, err = os.Pipe()
		if err != nil {
			return result, err
		}
		defer requestR.Close()
		defer requestW.Close()
		cmd.ExtraFiles = []*os.File{grantR, requestW}
		renewalDone = make(chan struct{})
		go func() {
			defer close(renewalDone)
			defer grantW.Close()
			scanner := bufio.NewScanner(requestR)
			scanner.Buffer(make([]byte, 64), 64)
			for scanner.Scan() {
				if scanner.Text() != "renew" {
					return
				}
				fresh, e := action.Renew(ctx)
				if e != nil || len(fresh) == 0 || len(fresh) > 3<<20 || !json.Valid(fresh) {
					return
				}
				if _, e = grantW.Write(append(fresh, '\n')); e != nil {
					return
				}
			}
		}()
	}
	start := time.Now()
	err = cmd.Start()
	if action != nil {
		grantR.Close()
		requestW.Close()
	}
	if err == nil {
		err = cmd.Wait()
	}
	if action != nil {
		cancel()
		requestR.Close()
		grantW.Close()
		<-renewalDone
	}
	// Also dispose of descendants after a parent exits normally.
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	result.DurationMS = time.Since(start).Milliseconds()
	result.ExitCode = 0
	if err != nil {
		result.ExitCode = -1
		if cmd.ProcessState != nil {
			result.ExitCode = cmd.ProcessState.ExitCode()
		}
	}
	result.TimedOut = ctx.Err() == context.DeadlineExceeded
	result.Stdout, result.Stderr = stdout.text(), stderr.text()
	if IsDisk(e.ID) {
		result.Stdout = ""
		if stdout.count <= int64(stdout.cap) {
			result.Stdout = RedactDiskJSON(stdout.buf.Bytes())
		}
	}
	if e.ID == "disk-deep-report-v1" {
		result.Stdout = ""
		result.Stderr = ""
	}
	result.StdoutTruncated, result.StderrTruncated = stdout.count > int64(e.OutputCap), stderr.count > int64(e.OutputCap)
	result.StdoutSHA256, result.StderrSHA256 = fmt.Sprintf("%x", stdout.digest.Sum(nil)), fmt.Sprintf("%x", stderr.digest.Sum(nil))
	return result, nil
}
