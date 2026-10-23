package signin

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

type Process interface {
	io.ReadWriteCloser
	Wait() error
	Kill()
}
type Launcher func(context.Context, model.SigninCommand, string) (Process, error)
type runSession struct {
	cancel    context.CancelFunc
	process   Process
	submitted bool
}

// Runner owns all login processes. It never emits raw CLI output.
type Runner struct {
	mu       sync.Mutex
	sessions map[string]*runSession
	seen     map[string]time.Time
	launch   Launcher
	home     string
	emit     func(model.SigninUpdate)
	probe    func(context.Context) []model.AuthHealth
}

func NewRunner(home string, launch Launcher, emit func(model.SigninUpdate), probe func(context.Context) []model.AuthHealth) *Runner {
	if launch == nil {
		launch = Launch
	}
	return &Runner{home: home, launch: launch, emit: emit, probe: probe, sessions: map[string]*runSession{}, seen: map[string]time.Time{}}
}
func (r *Runner) Handle(ctx context.Context, c model.SigninCommand) {
	if c.Operation == "probe" {
		return
	}
	r.mu.Lock()
	if c.Operation == "cancel" {
		if s := r.sessions[c.ID]; s != nil {
			s.cancel()
		}
		r.mu.Unlock()
		return
	}
	if c.Operation == "code" {
		s := r.sessions[c.ID]
		if s == nil || s.process == nil || s.submitted || !ValidPastedCode(c.Code) {
			r.mu.Unlock()
			return
		}
		s.submitted = true
		p := s.process
		r.mu.Unlock()
		_, _ = io.WriteString(p, c.Code+"\n")
		return
	}
	if c.Operation != "start" || !r.seen[c.ID].IsZero() {
		r.mu.Unlock()
		return
	}
	for id, until := range r.seen {
		if !until.After(time.Now()) {
			delete(r.seen, id)
		}
	}
	r.seen[c.ID] = c.ExpiresAt
	if len(r.sessions) >= 4 {
		r.mu.Unlock()
		r.emit(model.SigninUpdate{ID: c.ID, State: "failed", Reason: "limit"})
		return
	}
	if !supported(c.CLI, c.Slot) || !c.ExpiresAt.After(time.Now()) {
		r.mu.Unlock()
		return
	}
	deadline := c.ExpiresAt
	if max := time.Now().Add(15 * time.Minute); deadline.After(max) {
		deadline = max
	}
	runctx, cancel := context.WithDeadline(ctx, deadline)
	s := &runSession{cancel: cancel}
	r.sessions[c.ID] = s
	r.mu.Unlock()
	go r.run(runctx, c, s)
}
func supported(cli string, slot int) bool {
	return slot >= 1 && slot <= 8 && (cli == "agy" || slot == 1 && (cli == "codex" || cli == "claude" || cli == "gh" || cli == "grok"))
}
func (r *Runner) run(ctx context.Context, c model.SigninCommand, s *runSession) {
	defer func() { s.cancel(); r.mu.Lock(); delete(r.sessions, c.ID); r.mu.Unlock() }()
	home := r.home
	if c.CLI == "agy" && c.Slot > 1 {
		home = filepath.Join(home, ".gemini", "antigravity-accounts", "acct"+string(rune('0'+c.Slot))+"-home")
	}
	p, e := r.launch(ctx, c, home)
	if e != nil {
		r.emit(model.SigninUpdate{ID: c.ID, State: "failed", Reason: "start_failed"})
		return
	}
	defer p.Close()
	r.mu.Lock()
	s.process = p
	r.mu.Unlock()
	finished := make(chan struct{})
	defer close(finished)
	go func() {
		select {
		case <-ctx.Done():
			p.Kill()
		case <-finished:
		}
	}()
	// Rolling memory only; never write output to disk or a transport. Strip ANSI
	// before extracting fixed, allowlisted fields and closed-vocabulary markers.
	rolling := ""
	lastURL, lastCode := "", ""
	autoEnter := false
	failure := false
	success := false
	buf := make([]byte, 2048)
	for {
		n, err := p.Read(buf)
		if n > 0 {
			rolling += string(buf[:n])
			if len(rolling) > 16384 {
				rolling = rolling[len(rolling)-16384:]
			}
			text := ansiPattern.ReplaceAllString(rolling, "")
			low := strings.ToLower(text)
			if !autoEnter && (c.CLI == "agy" && strings.Contains(low, "google oauth") || c.CLI == "gh" && strings.Contains(low, "press enter")) {
				_, _ = io.WriteString(p, "\n")
				autoEnter = true
			}
			r.mu.Lock()
			submitted := s.submitted
			r.mu.Unlock()
			link, code, paste, browser := "", "", false, false
			if !submitted {
				link, code, paste, browser = Scrape(c.CLI, text)
			}
			if strings.Contains(low, "you are not logged into antigravity") || strings.Contains(low, "authentication failed") {
				failure = true
			}
			if c.CLI == "agy" && (strings.Contains(low, "successfully authenticated") || strings.Contains(low, "authentication successful") || strings.Contains(low, "logged in successfully") || strings.Contains(low, "successfully logged in")) {
				success = true
				failure = false
				p.Kill()
				break
			}
			if link != "" && link != lastURL || code != "" && code != lastCode || paste || browser {
				if link != "" {
					lastURL = link
				}
				if code != "" {
					lastCode = code
				}
				state, reason := "started", ""
				if paste && (c.CLI == "agy" || c.CLI == "claude" || c.CLI == "grok") {
					state = "waiting_for_code"
				}
				if browser {
					reason = "browser_required"
				}
				r.emit(model.SigninUpdate{ID: c.ID, State: state, URL: lastURL, DeviceCode: lastCode, Reason: reason})
				// Drop already parsed prompts to avoid repeated frames and retaining echoes.
				rolling = ""
			}
		}
		if err != nil {
			break
		}
	}
	err := p.Wait()
	// Stop the service even if the CLI exited while leaving descendants behind.
	p.Kill()
	state, reason := "done", "success"
	if (err != nil && !success) || failure {
		state = "failed"
		reason = "exit_failed"
		if failure && c.CLI == "agy" {
			reason = "logged_out"
		}
	}
	if ctx.Err() != nil {
		state = "failed"
		reason = "timeout"
	}
	update := model.SigninUpdate{ID: c.ID, State: state, Reason: reason}
	if r.probe != nil {
		probeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		update.Health = r.probe(probeCtx)
		for i := range update.Health {
			h := &update.Health[i]
			if h.CLI == c.CLI && h.Slot == c.Slot && failure {
				h.Status, h.Reason = "failing", "The login process reported an authentication failure"
			}
			if h.CLI == c.CLI && h.Slot == c.Slot && h.Status == "logged_out" && state == "done" {
				update.State, update.Reason = "failed", "not_configured"
			}
		}
		cancel()
	}
	r.emit(update)
}
func (r *Runner) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.sessions {
		s.cancel()
		if s.process != nil {
			s.process.Kill()
		}
	}
}

// Environment preserves the real user's executable search path even for pool HOME overrides.
func Environment(home, realHome string) []string {
	// Never copy credential-bearing environment variables into systemd-run's
	// command line or the login service. Only non-secret login necessities.
	return []string{"HOME=" + home, "PATH=" + filepath.Join(realHome, ".local", "bin") + ":" + filepath.Join(realHome, ".grok", "bin") + ":" + os.Getenv("PATH"), "BROWSER=/bin/true", "TERM=xterm-256color", "LANG=C.UTF-8"}
}
