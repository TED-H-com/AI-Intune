//go:build linux

package signin

import (
	"context"
	"encoding/json"
	"github.com/teddashh/AI-Intune/internal/model"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type scriptProcess struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  io.ReadCloser
	once sync.Once
}

func (p *scriptProcess) Read(b []byte) (int, error)  { return p.out.Read(b) }
func (p *scriptProcess) Write(b []byte) (int, error) { return p.in.Write(b) }
func (p *scriptProcess) Close() error                { p.in.Close(); return p.out.Close() }
func (p *scriptProcess) Wait() error                 { return p.cmd.Wait() }
func (p *scriptProcess) Kill() {
	p.once.Do(func() { _ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL); p.Close() })
}
func scriptLauncher(t *testing.T, script string) Launcher {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-cli")
	if e := os.WriteFile(path, []byte(script), 0600); e != nil {
		t.Fatal(e)
	}
	return func(ctx context.Context, c model.SigninCommand, home string) (Process, error) {
		cmd := exec.Command("/bin/sh", path)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Env = Environment(home, home)
		in, e := cmd.StdinPipe()
		if e != nil {
			return nil, e
		}
		out, e := cmd.StdoutPipe()
		if e != nil {
			return nil, e
		}
		cmd.Stderr = io.Discard
		if e = cmd.Start(); e != nil {
			return nil, e
		}
		return &scriptProcess{cmd: cmd, in: in, out: out}, nil
	}
}
func awaitUpdate(t *testing.T, ch <-chan model.SigninUpdate, state string) model.SigninUpdate {
	t.Helper()
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case u := <-ch:
			if u.State == state {
				return u
			}
		case <-deadline.C:
			t.Fatal("no update", state)
			return model.SigninUpdate{}
		}
	}
}
func TestRunnerFakeCLIOnlyRelaysAllowedFields(t *testing.T) {
	ch := make(chan model.SigninUpdate, 30)
	runner := NewRunner(t.TempDir(), scriptLauncher(t, "printf 'private-output-SYNTHETIC https://evil.example/no\\nhttps://accounts.google.com/o/oauth2/auth?test=1\\nPaste authorization code: '\nread code\n[ \"$code\" = 'example-code' ]\n"), func(u model.SigninUpdate) { ch <- u }, nil)
	defer runner.Shutdown()
	c := model.SigninCommand{ID: "fixture", CLI: "agy", Slot: 2, Operation: "start", ExpiresAt: time.Now().Add(time.Minute)}
	runner.Handle(context.Background(), c)
	u := awaitUpdate(t, ch, "waiting_for_code")
	b, _ := json.Marshal(u)
	if strings.Contains(string(b), "private-output") || strings.Contains(string(b), "evil.example") || u.URL == "" {
		t.Fatal(string(b))
	}
	c.Operation = "code"
	c.Code = "example-code"
	runner.Handle(context.Background(), c)
	runner.Handle(context.Background(), c)
	u = awaitUpdate(t, ch, "done")
	if u.Reason != "success" {
		t.Fatal(u)
	}
}
func TestRunnerTimeoutKillsWholeProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "escaped-child")
	ch := make(chan model.SigninUpdate, 8)
	runner := NewRunner(t.TempDir(), scriptLauncher(t, "(sleep 0.5; touch '"+marker+"') &\nwait\n"), func(u model.SigninUpdate) { ch <- u }, nil)
	defer runner.Shutdown()
	runner.Handle(context.Background(), model.SigninCommand{ID: "timeout", CLI: "codex", Slot: 1, Operation: "start", ExpiresAt: time.Now().Add(80 * time.Millisecond)})
	u := awaitUpdate(t, ch, "failed")
	if u.Reason != "timeout" {
		t.Fatal(u)
	}
	time.Sleep(600 * time.Millisecond)
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("child survived timeout")
	}
}
func TestRunnerConcurrencyAndShutdown(t *testing.T) {
	ch := make(chan model.SigninUpdate, 30)
	runner := NewRunner(t.TempDir(), scriptLauncher(t, "sleep 10\n"), func(u model.SigninUpdate) { ch <- u }, nil)
	for i := 0; i < 5; i++ {
		runner.Handle(context.Background(), model.SigninCommand{ID: string(rune('a' + i)), CLI: "codex", Slot: 1, Operation: "start", ExpiresAt: time.Now().Add(time.Minute)})
	}
	u := awaitUpdate(t, ch, "failed")
	if u.Reason != "limit" {
		t.Fatal(u)
	}
	runner.Shutdown()
}
func TestURLAndCodeAllowlist(t *testing.T) {
	for _, tc := range []struct {
		cli, url string
		ok       bool
	}{{"codex", "https://auth.openai.com/device", true}, {"codex", "https://auth.openai.com.evil.example/device", false}, {"agy", "https://accounts.google.com/o/oauth2", true}, {"agy", "https://evilgoogle.com/", false}, {"claude", "https://console.anthropic.com/oauth", true}, {"grok", "https://auth.x.ai/oauth", true}, {"gh", "https://github.com/login/device", true}, {"gh", "http://github.com/login/device", false}, {"gh", "https://secret@github.com/device", false}, {"gh", "https://github.com:443/device", false}} {
		if ValidURL(tc.cli, tc.url) != tc.ok {
			t.Fatal(tc)
		}
	}
	_, code, _, _ := Scrape("gh", "ABCD-EFGH https://github.com/login/device\n")
	if code != "ABCD-EFGH" {
		t.Fatal(code)
	}
	link, _, _, _ := Scrape("codex", "https://auth.openai.com/part")
	if link != "" {
		t.Fatal("partial URL emitted")
	}
	_, _, paste, browser := Scrape("grok", "http://localhost:3000 callback")
	if paste || !browser {
		t.Fatal("callback not detected")
	}
}

func TestLaunchUsesWritableUserManagerService(t *testing.T) {
	bin := t.TempDir()
	t.Setenv("PATH", bin)
	t.Setenv("HOME", t.TempDir())
	script := `#!/bin/sh
case " $* " in
 *" --user --pty --wait "*) ;;
 *) exit 21 ;;
esac
case " $* " in
 *" --property=KillMode=control-group "*) ;;
 *) exit 22 ;;
esac
case " $* " in
 *" --property=RuntimeMaxSec=900 "*) ;;
 *) exit 23 ;;
esac
printf 'https://accounts.google.com/oauth\nPaste authorization code: '
read code
[ "$code" = fixture-code ]
`
	for name, body := range map[string]string{"systemd-run": script, "systemctl": "#!/bin/sh\nexit 0\n"} {
		path := filepath.Join(bin, name)
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	ch := make(chan model.SigninUpdate, 10)
	r := NewRunner(t.TempDir(), nil, func(u model.SigninUpdate) { ch <- u }, nil)
	defer r.Shutdown()
	c := model.SigninCommand{ID: "manager-fixture", CLI: "agy", Slot: 2, Operation: "start", ExpiresAt: time.Now().Add(time.Minute)}
	r.Handle(context.Background(), c)
	awaitUpdate(t, ch, "waiting_for_code")
	c.Operation, c.Code = "code", "fixture-code"
	r.Handle(context.Background(), c)
	awaitUpdate(t, ch, "done")
}

func TestRunnerCompletesInteractiveSuccessWithoutWaitingForShellExit(t *testing.T) {
	ch := make(chan model.SigninUpdate, 10)
	r := NewRunner(t.TempDir(), scriptLauncher(t, "printf 'You are not logged into Antigravity\\nAuthentication successful\\n'\nsleep 30\n"), func(u model.SigninUpdate) { ch <- u }, nil)
	defer r.Shutdown()
	r.Handle(context.Background(), model.SigninCommand{ID: "interactive-success", CLI: "agy", Slot: 1, Operation: "start", ExpiresAt: time.Now().Add(time.Minute)})
	awaitUpdate(t, ch, "done")
}

func TestGitHubSuccessDoesNotInterruptSetupGit(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "setup-git-completed")
	ch := make(chan model.SigninUpdate, 10)
	r := NewRunner(t.TempDir(), scriptLauncher(t, "printf 'Successfully authenticated\\n'\nsleep 0.05\ntouch '"+marker+"'\n"), func(u model.SigninUpdate) { ch <- u }, nil)
	defer r.Shutdown()
	r.Handle(context.Background(), model.SigninCommand{ID: "github-setup", CLI: "gh", Slot: 1, Operation: "start", ExpiresAt: time.Now().Add(time.Minute)})
	awaitUpdate(t, ch, "done")
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("setup-git was interrupted", err)
	}
}

func TestRunnerFailureOverridesSavedCredentialEvidence(t *testing.T) {
	ch := make(chan model.SigninUpdate, 10)
	r := NewRunner(t.TempDir(), scriptLauncher(t, "printf 'You are not logged into Antigravity\\n'\nexit 1\n"), func(u model.SigninUpdate) { ch <- u }, func(context.Context) []model.AuthHealth {
		return []model.AuthHealth{{CLI: "agy", Slot: 2, Status: "ok"}, {CLI: "agy", Slot: 1, Status: "ok"}}
	})
	defer r.Shutdown()
	r.Handle(context.Background(), model.SigninCommand{ID: "provider-failure", CLI: "agy", Slot: 2, Operation: "start", ExpiresAt: time.Now().Add(time.Minute)})
	u := awaitUpdate(t, ch, "failed")
	if u.Reason != "logged_out" || len(u.Health) != 2 || u.Health[0].Status != "failing" || u.Health[1].Status != "ok" {
		t.Fatalf("failure not scoped to the affected account: %#v", u)
	}
}
