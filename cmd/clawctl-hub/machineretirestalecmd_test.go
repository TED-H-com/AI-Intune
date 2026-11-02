package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func retireStaleFixture(t *testing.T) (string, string) {
	t.Helper()
	path, active := directDBFixture(t)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC().Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at) VALUES(?,?,?)`, active, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE enrollment_tokens SET expires_at=?`, time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO machine_registry(machine_id,display_name,hostname,created_at) VALUES('stale','direct-machine','stale-host',?)`, time.Now().UTC().Add(-25*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	return path, active
}
func TestMachineRetireStaleDryRunAndApply(t *testing.T) {
	path, active := retireStaleFixture(t)
	read := func() (int, int, int) {
		t.Helper()
		db, err := sql.Open("sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		var retired, revision, audits int
		if err := db.QueryRow(`SELECT retired_at IS NOT NULL,lifecycle_revision FROM machine_registry WHERE machine_id='stale'`).Scan(&retired, &revision); err != nil {
			t.Fatal(err)
		}
		if err := db.QueryRow(`SELECT COUNT(*) FROM audit_log`).Scan(&audits); err != nil {
			t.Fatal(err)
		}
		return retired, revision, audits
	}
	beforeR, beforeV, beforeA := read()
	deps := productionMachineCommandDeps()
	deps.verifyHubStopped = func(context.Context, string) error { return nil }
	var out, errOut bytes.Buffer
	if err := runMachineCommandWithDeps(t.Context(), []string{"retire-stale", "--db", path}, &out, &errOut, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "stale") || !strings.Contains(out.String(), "Candidates: 1") {
		t.Fatalf("output=%s", out.String())
	}
	if r, v, a := read(); r != beforeR || v != beforeV || a != beforeA {
		t.Fatalf("dry run changed DB: %d %d %d", r, v, a)
	}
	out.Reset()
	if err := runMachineCommandWithDeps(t.Context(), []string{"retire-stale", "--db", path, "--apply"}, &out, &errOut, deps); err != nil {
		t.Fatal(err)
	}
	if r, v, a := read(); r != 1 || v != 1 || a != beforeA+1 {
		t.Fatalf("apply projection: %d %d %d", r, v, a)
	}
	st, err := openExisting(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	m, err := st.GetMachine(active)
	if err != nil || m.RetiredAt != nil {
		t.Fatalf("active=%+v err=%v", m, err)
	}
	audits, err := st.Audit("stale", 10)
	if err != nil || len(audits) != 1 {
		t.Fatalf("audits=%+v err=%v", audits, err)
	}
	a := audits[0]
	if a.Action != store.AuditMachineLifecycle || a.WhoUnavailable != "host-maintenance:retire-stale" || a.SourceAddr != "local-cli" || a.SourceKind != "direct-db-cli" || a.UserAgent != "clawctl-hub machine retire-stale" {
		t.Fatalf("audit=%+v", a)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM machine_registry_lifecycle_events WHERE machine_id='stale' AND event_type='retired'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("events=%d", n)
	}
}
func TestMachineRetireStaleContainerValidation(t *testing.T) {
	path, _ := retireStaleFixture(t)
	for _, apply := range []bool{false, true} {
		deps := productionMachineCommandDeps()
		deps.dockerenvPath = filepath.Join(t.TempDir(), "missing")
		args := []string{"retire-stale", "--db", path, "--container-stopped"}
		if apply {
			args = append(args, "--apply")
		}
		var out, errOut bytes.Buffer
		err := runMachineCommandWithDeps(t.Context(), args, &out, &errOut, deps)
		if err == nil {
			t.Fatal("expected rejection")
		}
		want := "requires --apply"
		if apply {
			want = "Docker marker required"
		}
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("err=%v", err)
		}
	}
}

func TestMachineRetireStaleJSONAndReadOnly(t *testing.T) {
	path, _ := retireStaleFixture(t)
	deps := machineCommandDeps{validateDirectPath: func(string) error { t.Fatal("dry-run entered apply fence"); return nil }}
	var out, errOut bytes.Buffer
	if err := runMachineCommandWithDeps(t.Context(), []string{"retire-stale", "--db", path, "--json"}, &out, &errOut, deps); err != nil {
		t.Fatal(err)
	}
	var result struct {
		Mode       string                        `json:"mode"`
		Candidates []store.StaleMachineCandidate `json:"candidates"`
	}
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Mode != "dry-run" || len(result.Candidates) != 1 || len(result.Candidates[0].Branches) != 2 {
		t.Fatalf("result=%+v", result)
	}
	db, err := store.OpenStaleMachineReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`DELETE FROM machine_registry WHERE machine_id='stale'`); err == nil {
		t.Fatal("read-only connection allowed write")
	}
}
