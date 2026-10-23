//go:build linux

package signin

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

var ansiPattern = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07]*(?:\x07)`)
var unitID = regexp.MustCompile(`^[a-zA-Z0-9-]{1,64}$`)

// Launch asks the USER MANAGER to create a new service and PTY. A scope or
// direct child would inherit ProtectHome and NoNewPrivileges from the agent.
// The service starts outside that mount namespace, just like bat-server's shells.
func Launch(ctx context.Context, c model.SigninCommand, home string) (Process, error) {
	if !unitID.MatchString(c.ID) || !supported(c.CLI, c.Slot) {
		return nil, fmt.Errorf("invalid sign-in command")
	}
	args := map[string][]string{"codex": {"codex", "login", "--device-auth"}, "agy": {"agy"}, "claude": {"claude", "setup-token"}, "grok": {"grok", "login", "--oauth"}, "gh": {"gh", "auth", "login", "--hostname", "github.com", "--git-protocol", "https", "--web", "--skip-ssh-key"}}[c.CLI]
	if c.CLI == "gh" {
		args = []string{"/bin/sh", "-c", "gh auth login --hostname github.com --git-protocol https --web --skip-ssh-key && gh auth setup-git"}
	}
	realHome, e := os.UserHomeDir()
	if e != nil {
		return nil, e
	}
	unit := "clawctl-signin-" + c.ID + ".service"
	wrapped := []string{"--user", "--pty", "--wait", "--quiet", "--collect", "--service-type=exec", "--unit=" + unit, "--property=RuntimeMaxSec=900", "--property=TimeoutStopSec=3", "--property=KillMode=control-group", "--property=SendSIGKILL=yes"}
	// With --pty, systemd connects stdout/stderr to the PTY; explicitly avoid
	// journal capture. Environment is arguments to systemd-run, never a shell.
	for _, v := range Environment(home, realHome) {
		wrapped = append(wrapped, "--setenv="+v)
	}
	wrapped = append(wrapped, "--", "/usr/bin/env")
	wrapped = append(wrapped, args...)
	cmd := exec.Command("systemd-run", wrapped...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	input, e := cmd.StdinPipe()
	if e != nil {
		return nil, e
	}
	output, e := cmd.StdoutPipe()
	if e != nil {
		input.Close()
		return nil, e
	}
	cmd.Stderr = io.Discard
	if e = cmd.Start(); e != nil {
		input.Close()
		output.Close()
		return nil, e
	}
	return &serviceProcess{cmd: cmd, in: input, out: output, unit: unit}, nil
}

type serviceProcess struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    io.ReadCloser
	unit   string
	waited atomic.Bool
}

func (p *serviceProcess) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *serviceProcess) Write(b []byte) (int, error) { return p.in.Write(b) }
func (p *serviceProcess) Close() error                { p.in.Close(); return p.out.Close() }
func (p *serviceProcess) Wait() error {
	e := p.cmd.Wait()
	p.waited.Store(true)
	// gh setup-git runs in the same writable user-manager context, after auth.
	return e
}
func (p *serviceProcess) Kill() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = exec.CommandContext(ctx, "systemctl", "--user", "stop", p.unit).Run()
	if !p.waited.Load() {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	}
	p.Close()
}
