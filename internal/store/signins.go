package store

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/signin"
)

type signinMemory struct {
	sync.Mutex
	updates map[string]model.SigninUpdate
	codes   map[string]string
	send    func(string, model.SigninCommand) error
}

type SigninSession struct {
	ID        string    `json:"id"`
	MachineID string    `json:"machine_id"`
	CLI       string    `json:"cli"`
	Slot      int       `json:"slot"`
	State     string    `json:"state"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Reason    string    `json:"reason"`
}

func SigninSupported(cli string, slot int) bool {
	return slot >= 1 && slot <= 8 && (cli == "agy" || slot == 1 && (cli == "codex" || cli == "claude" || cli == "grok" || cli == "gh"))
}
func activeSignin(state string) bool {
	return state == "pending" || state == "started" || state == "waiting_for_code" || state == "submitted"
}
func (s *Store) SetSigninTransport(send func(string, model.SigninCommand) error) {
	s.signins.Lock()
	defer s.signins.Unlock()
	s.signins.send = send
}
func (s *Store) SigninSessions() ([]SigninSession, error) {
	rows, e := s.rdb.Query(`SELECT id,machine_id,cli,slot,state,created_at,expires_at,reason FROM signin_sessions WHERE state IN ('pending','started','waiting_for_code','submitted') OR created_at>=? ORDER BY created_at DESC`, fmtTime(s.now().Add(-15*time.Minute)))
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	out := []SigninSession{}
	for rows.Next() {
		var v SigninSession
		var created, expiry string
		if e = rows.Scan(&v.ID, &v.MachineID, &v.CLI, &v.Slot, &v.State, &created, &expiry, &v.Reason); e != nil {
			return nil, e
		}
		v.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
		v.ExpiresAt, _ = time.Parse(time.RFC3339Nano, expiry)
		out = append(out, v)
	}
	return out, rows.Err()
}
func (s *Store) StartSignin(ctx context.Context, machine, cli string, slot int, a AuditEntry) (SigninSession, error) {
	v := SigninSession{ID: uuid.NewString(), MachineID: machine, CLI: cli, Slot: slot, State: "pending", CreatedAt: s.now()}
	v.ExpiresAt = v.CreatedAt.Add(15 * time.Minute)
	if !SigninSupported(cli, slot) {
		return v, errors.New("sign-in is not supported")
	}
	tx, e := s.beginWrite(ctx, "signin_start")
	if e != nil {
		return v, e
	}
	defer tx.Rollback()
	if e := executionAllowedTx(tx, machine); e != nil {
		return v, e
	}
	var osname string
	if e = tx.QueryRow(`SELECT os FROM machine_registry WHERE machine_id=? AND retired_at IS NULL`, machine).Scan(&osname); e != nil {
		return v, e
	}
	if osname != "linux" {
		return v, errors.New("Hub sign-in requires a Linux agent")
	}
	// Expiry is audited in the same transaction, including when a new session replaces it.
	if e = s.expireSigninsTx(tx, v.CreatedAt); e != nil {
		return v, e
	}
	_, e = tx.Exec(`INSERT INTO signin_sessions(id,machine_id,cli,slot,state,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, v.ID, machine, cli, slot, v.State, fmtTime(v.CreatedAt), fmtTime(v.ExpiresAt))
	if e != nil {
		return v, errors.New("a sign-in is already active for this account")
	}
	a.At = v.CreatedAt
	a.Action = AuditSigninStart
	a.MachineID = machine
	a.Subject = v.ID
	a.Detail = cli + " slot " + strconv.Itoa(slot)
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return v, e
	}
	return v, tx.Commit()
}
func (s *Store) expireSigninsTx(tx dbTx, now time.Time) error {
	rows, e := tx.Query(`SELECT id,machine_id FROM signin_sessions WHERE state IN ('pending','started','waiting_for_code','submitted') AND expires_at<=?`, fmtTime(now))
	if e != nil {
		return e
	}
	var ids [][2]string
	for rows.Next() {
		var id, m string
		if e = rows.Scan(&id, &m); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, [2]string{id, m})
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	for _, v := range ids {
		if _, e = tx.Exec(`UPDATE signin_sessions SET state='expired',reason='Sign-in timed out' WHERE id=?`, v[0]); e != nil {
			return e
		}
		if e = s.recordAuditTx(tx, AuditEntry{At: now, Action: AuditSigninResult, MachineID: v[1], Subject: v[0], Detail: "expired", OK: false}); e != nil {
			return e
		}
	}
	return nil
}
func (s *Store) ExpireSignins() error {
	tx, e := s.beginWrite(context.Background(), "signin_expiry")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.expireSigninsTx(tx, s.now()); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	s.signins.Lock()
	defer s.signins.Unlock()
	list, _ := s.SigninSessions()
	active := map[string]bool{}
	for _, v := range list {
		if activeSignin(v.State) {
			active[v.ID] = true
		}
	}
	for id := range s.signins.codes {
		if !active[id] {
			delete(s.signins.codes, id)
		}
	}
	for id := range s.signins.updates {
		if !active[id] {
			delete(s.signins.updates, id)
		}
	}
	return nil
}
func (s *Store) SigninAction(ctx context.Context, id, op, code string, a AuditEntry) error {
	s.signins.Lock()
	defer s.signins.Unlock()
	tx, e := s.beginWrite(ctx, "signin_action")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state, machine string
	var expiry string
	if e = tx.QueryRow(`SELECT state,machine_id,expires_at FROM signin_sessions WHERE id=?`, id).Scan(&state, &machine, &expiry); e != nil {
		return e
	}
	if e = executionAllowedTx(tx, machine); e != nil {
		return e
	}
	until, _ := time.Parse(time.RFC3339Nano, expiry)
	if !activeSignin(state) || !until.After(s.now()) {
		return errors.New("sign-in has ended")
	}
	next := "cancelled"
	action := AuditSigninCancel
	if op == "code" {
		if state != "waiting_for_code" || !signin.ValidPastedCode(code) {
			return errors.New("invalid sign-in code")
		}
		next = "submitted"
		action = AuditSigninCodeSubmitted
	} else if op != "cancel" {
		return errors.New("invalid sign-in action")
	}
	if _, e = tx.Exec(`UPDATE signin_sessions SET state=? WHERE id=?`, next, id); e != nil {
		return e
	}
	a.At = s.now()
	a.Action = action
	a.MachineID = machine
	a.Subject = id
	a.Detail = next
	a.Reason = ""
	a.OK = true
	if e = s.recordAuditTx(tx, a); e != nil {
		return e
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if op == "code" {
		if s.signins.codes == nil {
			s.signins.codes = map[string]string{}
		}
		s.signins.codes[id] = code
	} else {
		delete(s.signins.codes, id)
		delete(s.signins.updates, id)
	}
	return nil
}

// SigninCommands claims pending work and consumes pasted codes exactly once.
// No code appears in SQL, audit, disk queues, or retry payloads.
func (s *Store) SigninCommands(machine string) []model.SigninCommand {
	if s.MachineExecutionAllowed(machine) != nil {
		return nil
	}
	_ = s.ExpireSignins()
	s.signins.Lock()
	defer s.signins.Unlock()
	list, e := s.SigninSessions()
	if e != nil {
		return nil
	}
	out := []model.SigninCommand{}
	for _, v := range list {
		if v.MachineID != machine {
			continue
		}
		op := ""
		code := ""
		switch v.State {
		case "pending":
			op = "start"
		case "submitted":
			code = s.signins.codes[v.ID]
			if code != "" {
				op = "code"
				delete(s.signins.codes, v.ID)
			}
		case "cancelled", "expired":
			op = "cancel"
		}
		if op == "" {
			continue
		}
		if op == "start" {
			res, e := s.execWrite(context.Background(), "signin_claim", `UPDATE signin_sessions SET state='started' WHERE id=? AND state='pending'`, v.ID)
			if e != nil {
				continue
			}
			n, _ := res.RowsAffected()
			if n != 1 {
				continue
			}
		}
		out = append(out, model.SigninCommand{ID: v.ID, CLI: v.CLI, Slot: v.Slot, Operation: op, ExpiresAt: v.ExpiresAt, Code: code})
	}
	return out
}
func (s *Store) DispatchSignins(machine string) {
	if s.MachineExecutionAllowed(machine) != nil {
		return
	}
	s.signins.Lock()
	send := s.signins.send
	s.signins.Unlock()
	if send == nil {
		return
	}
	// Check link availability before claiming any work; probe command has no side effects.
	if send(machine, model.SigninCommand{Operation: "probe"}) != nil {
		return
	}
	for _, c := range s.SigninCommands(machine) {
		if send(machine, c) != nil {
			_ = s.UpdateSignin(machine, model.SigninUpdate{ID: c.ID, State: "failed", Reason: "delivery_failed"})
		}
	}
}
func (s *Store) SigninDisplay(id string) model.SigninUpdate {
	s.signins.Lock()
	defer s.signins.Unlock()
	return s.signins.updates[id]
}
func (s *Store) UpdateSignin(machine string, u model.SigninUpdate) error {
	s.signins.Lock()
	defer s.signins.Unlock()
	tx, e := s.beginWrite(context.Background(), "signin_update")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	var state, cli, expiry string
	if e = tx.QueryRow(`SELECT state,cli,expires_at FROM signin_sessions WHERE id=? AND machine_id=?`, u.ID, machine).Scan(&state, &cli, &expiry); e != nil {
		return e
	}
	if e = executionAllowedTx(tx, machine); e != nil {
		return e
	}
	until, _ := time.Parse(time.RFC3339Nano, expiry)
	if !activeSignin(state) || !until.After(s.now()) {
		return errors.New("sign-in has ended")
	}
	// Ignore arbitrary agent reasons. Closed vocabulary prevents secret-bearing diagnostics.
	reasons := map[string]string{"success": "Sign-in completed", "exit_failed": "The CLI could not complete sign-in", "timeout": "Sign-in timed out", "cancelled": "Sign-in cancelled", "delivery_failed": "Agent connection interrupted", "limit": "Four sign-ins are already running", "start_failed": "The CLI could not be started", "browser_required": "Finish in a browser on that machine is required", "logged_out": "You are not logged into Antigravity", "not_configured": "The CLI exited but no saved sign-in was found"}
	reason := reasons[u.Reason]
	if u.State != "waiting_for_code" && u.State != "started" && u.State != "done" && u.State != "failed" {
		return errors.New("invalid sign-in result")
	}
	if state == "pending" {
		return errors.New("sign-in has not started")
	}
	if (state == "waiting_for_code" && u.State == "started") || (state == "submitted" && (u.State == "waiting_for_code" || u.State == "started")) {
		return nil
	}
	if _, e = tx.Exec(`UPDATE signin_sessions SET state=?,reason=? WHERE id=?`, u.State, reason, u.ID); e != nil {
		return e
	}
	if u.State == "done" || u.State == "failed" {
		if e = s.recordAuditTx(tx, AuditEntry{At: s.now(), Action: AuditSigninResult, MachineID: machine, Subject: u.ID, Detail: u.State, OK: u.State == "done"}); e != nil {
			return e
		}
		delete(s.signins.codes, u.ID)
	}
	if e = tx.Commit(); e != nil {
		return e
	}
	if s.signins.updates == nil {
		s.signins.updates = map[string]model.SigninUpdate{}
	}
	// URL/code validation is shared with the agent, repeated at this trust boundary.
	u.Reason = reason
	u.Health = nil
	if !ValidSigninURL(cli, u.URL) {
		u.URL = ""
	}
	if !ValidDeviceCode(cli, u.DeviceCode) {
		u.DeviceCode = ""
	}
	if u.State == "done" || u.State == "failed" {
		u.URL = ""
		u.DeviceCode = ""
	}
	s.signins.updates[u.ID] = u
	return nil
}

type SigninHost struct {
	MachineID   string `json:"machine_id"`
	DisplayName string `json:"display_name"`
	MonitorOnly bool   `json:"monitor_only,omitempty"`
	model.AuthHealth
}
type SigninGroup struct {
	CLI     string       `json:"cli"`
	Account string       `json:"account,omitempty"`
	Slot    int          `json:"slot,omitempty"`
	Hosts   []SigninHost `json:"hosts"`
	Needs   int          `json:"needs"`
}

func (s *Store) Signins() ([]SigninGroup, error) {
	rows, e := s.rdb.Query(`SELECT o.machine_id,m.display_name,m.execution_policy<>'managed',o.payload FROM observed_latest o JOIN machine_registry m ON m.machine_id=o.machine_id WHERE o.kind='auth_health' AND m.retired_at IS NULL ORDER BY m.display_name`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	groups := map[string]*SigninGroup{}
	for rows.Next() {
		var h SigninHost
		var payload string
		if e = rows.Scan(&h.MachineID, &h.DisplayName, &h.MonitorOnly, &payload); e != nil {
			return nil, e
		}
		if json.Unmarshal([]byte(payload), &h.AuthHealth) != nil {
			continue
		}
		key := h.CLI + "/" + strings.ToLower(h.Account)
		if h.Account == "" {
			key += "/" + strconv.Itoa(h.Slot)
		}
		g := groups[key]
		if g == nil {
			g = &SigninGroup{CLI: h.CLI, Account: h.Account, Slot: h.Slot}
			groups[key] = g
		}
		g.Hosts = append(g.Hosts, h)
		if h.Status == "logged_out" || h.Status == "failing" || h.Status == "expiring" {
			g.Needs++
		}
	}
	out := []SigninGroup{}
	for _, g := range groups {
		out = append(out, *g)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CLI != out[j].CLI {
			return out[i].CLI < out[j].CLI
		}
		if out[i].Account != out[j].Account {
			return out[i].Account < out[j].Account
		}
		return out[i].Slot < out[j].Slot
	})
	return out, rows.Err()
}

// RecordSigninHealth records the same metadata-only facts as an observation.
func (s *Store) RecordSigninHealth(machine string, health []model.AuthHealth, now time.Time) error {
	tx, e := s.beginWrite(context.Background(), "signin_health")
	if e != nil {
		return e
	}
	defer tx.Rollback()
	if e = s.signinNotificationFacts(tx, machine, health, now); e != nil {
		return e
	}
	for _, h := range health {
		if !SigninSupported(h.CLI, h.Slot) && h.CLI != "hermes-openai-codex" {
			continue
		}
		if len(h.Account) > 254 || len(h.Reason) > 256 {
			continue
		}
		switch h.Status {
		case "ok", "expiring", "logged_out", "failing", "unknown":
		default:
			continue
		}
		b, e := json.Marshal(h)
		if e != nil {
			return e
		}
		_, e = tx.Exec(`INSERT INTO observed_state(observation_id,machine_id,measured_at,received_at,kind,subject,payload,source) VALUES(?,?,?,?,?,?,?,?)`, uuid.NewString(), machine, fmtTime(now), fmtTime(now), "auth_health", h.CLI+"/"+strconv.Itoa(h.Slot), string(b), SourceAgentMeasurement)
		if e != nil {
			return e
		}
	}
	return tx.Commit()
}

// putSigninHealth keeps check-in wiring small and shares notification transitions.
func (s *Store) putSigninHealth(tx dbTx, machine string, health []model.AuthHealth, now time.Time, put func(string, string, any) error) error {
	if err := s.signinNotificationFacts(tx, machine, health, now); err != nil {
		return err
	}
	for _, h := range health {
		if err := put("auth_health", h.CLI+"/"+strconv.Itoa(h.Slot), h); err != nil {
			return err
		}
	}
	return nil
}
