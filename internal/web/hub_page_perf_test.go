package web

// Portable page fixture: this file also compiles on defb4f8. The optional
// TraceSQL hook adds statement timings on checkouts that implement it.
// CLAWCTL_PERF=1 GOPROXY=off GOTOOLCHAIN=local go test -run '^TestHubPagePerf$' -v ./internal/web
import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
	"github.com/teddashh/AI-Intune/internal/store"
	"github.com/teddashh/AI-Intune/internal/tailnet"
)

type pagePerfStatement struct {
	query   string
	args    []any
	elapsed time.Duration
}

func TestHubPagePerf(t *testing.T) {
	if os.Getenv("CLAWCTL_PERF") != "1" {
		t.Skip("set CLAWCTL_PERF=1")
	}
	dir := t.TempDir()
	original := filepath.Join(dir, "fixture.db")
	st, err := store.Open(original)
	if err != nil {
		t.Fatal(err)
	}
	pagePerfSeed(t, st.DB())
	if err = st.Close(); err != nil {
		t.Fatal(err)
	} // checkpoint WAL before copying
	t.Log("PERF synthetic machines=60 observations=430200 days=30; cold=fresh file copy and reopened Store; OS page cache is NOT dropped, and Open/migrations can warm it")
	for i, path := range []string{"/", "/machines", "/checks", "/machines/perf-00", "/reports/software", "/jobs", "/audit"} {
		copyPath := filepath.Join(dir, fmt.Sprintf("page-%d.db", i))
		pagePerfCopy(t, original, copyPath)
		s, err := store.Open(copyPath)
		if err != nil {
			t.Fatal(err)
		}
		func() {
			defer s.Close()
			server, err := New(s, "")
			if err != nil {
				t.Fatal(err)
			}
			server.SetArtifactsDir(dir)
			server.SetTailnetStatus(tailnet.Status{})
			mux := http.NewServeMux()
			server.Routes(mux)
			var mu sync.Mutex
			var statements []pagePerfStatement
			record := true
			if traced, ok := any(s).(interface {
				TraceSQL(func(string, []any, time.Duration)) error
			}); ok {
				err = traced.TraceSQL(func(q string, a []any, d time.Duration) {
					mu.Lock()
					defer mu.Unlock()
					if record {
						statements = append(statements, pagePerfStatement{q, a, d})
					}
				})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				t.Log("PERF SQL tracer unavailable on this checkout; page timings remain comparable")
			}
			render := func() time.Duration {
				req := verifiedWebRequest(httptest.NewRequest(http.MethodGet, path, nil), "example.com/cap/clawctl-admin")
				rec := httptest.NewRecorder()
				start := time.Now()
				mux.ServeHTTP(rec, req)
				elapsed := time.Since(start)
				if rec.Code != 200 || !strings.Contains(rec.Body.String(), "</html>") {
					t.Fatalf("page %s status=%d incomplete=%t", path, rec.Code, !strings.Contains(rec.Body.String(), "</html>"))
				}
				return elapsed
			}
			cold := render()
			mu.Lock()
			record = false
			mu.Unlock()
			warm := make([]time.Duration, 5)
			for j := range warm {
				warm[j] = render()
			}
			sort.Slice(warm, func(i, j int) bool { return warm[i] < warm[j] })
			t.Logf("PERF page path=%s cold=%s warm_p50=%s", path, cold, warm[2])
			for _, q := range statements {
				t.Logf("SQL page=%s duration=%s statement=%s", path, q.elapsed, strings.Join(strings.Fields(q.query), " "))
			}
			sort.Slice(statements, func(i, j int) bool { return statements[i].elapsed > statements[j].elapsed })
			seen := map[string]bool{}
			// Explain every distinct SELECT, including fast queries: a warm cache can
			// disguise a scan. The slowest statements appear first.
			for _, q := range statements {
				if seen[q.query] {
					continue
				}
				seen[q.query] = true
				upper := strings.ToUpper(strings.TrimSpace(q.query))
				if !strings.HasPrefix(upper, "SELECT") && !strings.HasPrefix(upper, "WITH") {
					continue
				}
				rows, e := s.DB().Query("EXPLAIN QUERY PLAN "+q.query, q.args...)
				if e != nil {
					t.Fatalf("explain %q: %v", q.query, e)
				}
				for rows.Next() {
					var id, parent, unused int
					var detail string
					if e = rows.Scan(&id, &parent, &unused, &detail); e != nil {
						t.Fatal(e)
					}
					t.Logf("PLAN page=%s duration=%s statement=%s detail=%s", path, q.elapsed, strings.Join(strings.Fields(q.query), " "), detail)
				}
				if e = rows.Err(); e != nil {
					t.Fatal(e)
				}
				rows.Close()
			}
		}()
		if err = os.Remove(copyPath); err != nil {
			t.Fatal(err)
		}
	}
}

func pagePerfCopy(t *testing.T, source, dest string) {
	t.Helper()
	in, e := os.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	out, e := os.Create(dest)
	if e != nil {
		t.Fatal(e)
	}
	_, e = io.Copy(out, in)
	closeErr := out.Close()
	if e != nil {
		t.Fatal(e)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
}

func pagePerfSeed(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := tx.Exec(q, args...); e != nil {
			t.Fatal(e)
		}
	}
	now := time.Now().UTC().Truncate(time.Second).Add(-time.Minute)
	stamp := func(at time.Time) string { return at.UTC().Format(time.RFC3339) }
	type sample struct{ kind, subject, payload string }
	var samples []sample
	add := func(kind, subject string, value any, size int) {
		raw, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		var fields map[string]any
		if e = json.Unmarshal(raw, &fields); e != nil {
			t.Fatal(e)
		}
		fields["perf_padding"] = strings.Repeat("synthetic ", size/10)
		raw, e = json.Marshal(fields)
		if e != nil {
			t.Fatal(e)
		}
		samples = append(samples, sample{kind, subject, string(raw)})
	}
	b := batch(now)
	add("identity", "identity", b.Identity, 512)
	add("resources", "resources", b.Resources, 512)
	add("openclaw", "openclaw", b.OpenClaw, 3072)
	add("bat", "bat", b.BAT, 1024)
	add("host_profile_apply", "host_profile_apply", model.HostApplyResult{}, 1024)
	add("host_readiness", "host_readiness", model.ReadinessFacts{}, 1024)
	for i := 0; i < 100; i++ {
		name := fmt.Sprintf("unit-%03d.service", i)
		add("systemd", name, model.Unit{Name: name, Present: true, ActiveState: "active", SubState: "running"}, 512)
	}
	for i := 0; i < 20; i++ {
		name := fmt.Sprintf("tool-%02d", i)
		if i == 0 {
			name = "openclaw"
		}
		add("cli_tool", name, model.CLITool{Name: name, Present: true, Path: "/usr/bin/" + name, VersionReported: "1.2.3"}, 1024)
	}
	for _, provider := range []string{"claude", "codex", "gemini"} {
		mtime := now.Add(-24 * time.Hour)
		expiry := now.Add(24 * time.Hour)
		add("credential", provider, model.Credential{Provider: provider, Status: model.CredConfigured, FileMTime: &mtime, ExpiresAt: &expiry}, 512)
	}
	add("artifact", "example", model.ArtifactCheck{}, 1024)
	add("journal", "openclaw.service", model.UnitJournal{}, 3072)
	insert, err := tx.Prepare(`INSERT INTO observed_state(observation_id,machine_id,measured_at,received_at,kind,subject,payload,source) VALUES(?,?,?,?,?,?,?,?)`)
	if err != nil {
		t.Fatal(err)
	}
	defer insert.Close()
	// 60 * 239 * 30 = 430200. Subjects recur at each daily snapshot;
	// systemd/CLI dominate rows while JSON remains 0.5-4KB.
	for m := 0; m < 60; m++ {
		id := fmt.Sprintf("perf-%02d", m)
		exec(`INSERT INTO machine_registry(machine_id,display_name,hostname,os,arch,unix_user,expected,created_at,enrolled_at) VALUES(?,?,?,'linux','amd64','synthetic',1,?,?)`, id, id, id, stamp(now.Add(-30*24*time.Hour)), stamp(now.Add(-30*24*time.Hour)))
		for day := 0; day < 30; day++ {
			at := now.Add(-time.Duration(29-day) * 24 * time.Hour)
			for n := 0; n < 239; n++ {
				sample := samples[n%len(samples)]
				when := stamp(at.Add(-time.Duration(239-n) * time.Second))
				if _, err = insert.Exec(fmt.Sprintf("%s-%d-%d", id, day, n), id, when, when, sample.kind, sample.subject, sample.payload, "agent_measurement"); err != nil {
					t.Fatal(err)
				}
			}
			for check := 0; check < 24; check++ {
				when := stamp(at.Add(-time.Duration(23-check) * time.Hour))
				exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at,agent_version,boot_id,agent_started_at,jobs_enabled) VALUES(?,?,?,'perf','synthetic-boot',?,1)`, id, when, when, stamp(at.Add(-24*time.Hour)))
			}
			entered := stamp(at.Add(-time.Hour))
			var left any
			if day < 29 {
				left = stamp(at)
			}
			exec(`INSERT INTO machine_state_history(machine_id,state,reason,entered_at,left_at) VALUES(?,'Online','synthetic',?,?)`, id, entered, left)
			desired := fmt.Sprintf("desired-%s-%d", id, day)
			exec(`INSERT INTO desired_state(desired_id,scope_type,scope_id,resource_kind,resource_id,revision,spec,created_at,created_by) VALUES(?,'machine',?,'package',?,1,'{"kind":"noop"}',?,'synthetic')`, desired, id, desired, stamp(at))
			// Failed jobs are valid without verifier evidence; succeeded jobs require
			// a complete all-passing verification set in the production read model.
			exec(`INSERT INTO jobs(job_id,machine_id,desired_id,revision,state,created_at,terminal_at) VALUES(?,?,?,1,'failed',?,?)`, fmt.Sprintf("job-%s-%d", id, day), id, desired, stamp(at), stamp(at))
			exec(`INSERT INTO audit_log(at,action,machine_id,subject,source_addr,outcome) VALUES(?,'perf',?,?,'synthetic','ok')`, stamp(at), id, id)
		}
	}
	if err = tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec("ANALYZE"); err != nil {
		t.Fatal(err)
	}
}
