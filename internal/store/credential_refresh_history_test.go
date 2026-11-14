package store

import (
	"database/sql"
	"errors"
	"fmt"
	"math/rand"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// credRefreshHistoryReferenceSQL is the statement credRefreshHistorySQL
// replaced. It reads every retained credential observation.
const credRefreshHistoryReferenceSQL = `
SELECT o.machine_id,
       COALESCE(NULLIF(m.display_name, ''), o.machine_id),
       o.subject,
       COUNT(DISTINCT json_extract(o.payload, '$.file_mtime')),
       MIN(o.measured_at),
       MAX(json_extract(o.payload, '$.file_mtime')),
       CASE WHEN m.retired_at IS NULL THEN 0 ELSE 1 END
  FROM observed_state o
  JOIN machine_registry m ON m.machine_id = o.machine_id
 WHERE o.kind = 'credential' AND o.received_at <= ?
 GROUP BY o.machine_id, m.display_name, o.subject, m.retired_at`

func credHistoryRows(t *testing.T, st *Store, query, at string, columns int) ([]string, error) {
	t.Helper()
	rows, err := st.DB().Query(query, at)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []string
	for rows.Next() {
		values := make([]any, len(names))
		targets := make([]any, len(names))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			return nil, err
		}
		parts := make([]string, columns)
		for i := range parts {
			parts[i] = fmt.Sprintf("%T:%v", values[i], values[i])
		}
		out = append(out, strings.Join(parts, "|"))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

func referenceCredRefreshHistory(t *testing.T, st *Store, at time.Time) (credRefreshFleet, error) {
	t.Helper()
	rows, err := st.DB().Query(credRefreshHistoryReferenceSQL, fmtTime(at))
	if err != nil {
		return nil, fmt.Errorf("store: credential refresh history: %w", err)
	}
	defer rows.Close()
	out := credRefreshFleet{}
	for rows.Next() {
		var machineID, displayName, subject, first string
		var distinct, retired int
		var fileMTime sql.NullString
		if err := rows.Scan(&machineID, &displayName, &subject, &distinct, &first, &fileMTime, &retired); err != nil {
			return nil, fmt.Errorf("store: scan credential refresh history: %w", err)
		}
		h := credRefresh{DisplayName: displayName, FirstSeen: parseTime(first), FileMTime: parseTimePtr(fileMTime), Retired: retired != 0}
		if distinct > 1 {
			h.Refreshes = distinct - 1
		}
		if out[machineID] == nil {
			out[machineID] = map[string]credRefresh{}
		}
		out[machineID][subject] = h
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate credential refresh history: %w", err)
	}
	return out, nil
}

func insertCredHistoryMachine(t *testing.T, st *Store, id, name string, retired any) {
	t.Helper()
	if _, err := st.DB().Exec(`INSERT INTO machine_registry (machine_id, display_name, created_at, retired_at) VALUES (?,?,?,?)`, id, name, "2026-10-01T00:00:00Z", retired); err != nil {
		t.Fatal(err)
	}
}

func insertCredHistoryObservation(t *testing.T, st *Store, id, machine, subject, kind, measured, received string, payload any) {
	t.Helper()
	if _, err := st.DB().Exec(`INSERT INTO observed_state(observation_id,machine_id,measured_at,received_at,kind,subject,payload,source) VALUES(?,?,?,?,?,?,?,?)`, id, machine, measured, received, kind, subject, payload, "agent_measurement"); err != nil {
		t.Fatal(err)
	}
}

func TestCredRefreshHistoryMatchesReference(t *testing.T) {
	st := newTestStore(t)
	rng := rand.New(rand.NewSource(20261114))
	t0 := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	pool := []string{`{"provider":"x"}`, `{"file_mtime":null}`, `{"file_mtime":""}`, `{"file_mtime":"2026-11-01T00:00:00Z"}`, `{"file_mtime":"2026-11-02T00:00:00Z"}`, `{"file_mtime":"2026-11-03T00:00:00.5+08:00"}`, `{"file_mtime":"2026-11-01T00:00:00Z","status":"ok"}`, `{"file_mtime":7}`, `{"file_mtime":7.5}`, `{"file_mtime":true}`, `{"file_mtime":{"a":1}}`, `{"file_mtime":[1,2]}`, `{"file_mtime":"a","file_mtime":"b"}`, `[1,2]`, `"text"`}
	subjects := []string{"", "claude", "claude-2", "codex", "克勞德"}
	var last []string
	for r := 0; r < credRefreshHistoryRounds; r++ {
		n := 0
		for _, suffix := range []string{"a", "a1", "b"}[:1+rng.Intn(3)] {
			id := fmt.Sprintf("r%03d-%s", r, suffix)
			name := []string{"", "alpha", "alpha", fmt.Sprintf("name-%d", r)}[rng.Intn(4)]
			var retired any
			if rng.Intn(4) == 0 {
				retired = "2026-11-01T00:00:00Z"
			}
			insertCredHistoryMachine(t, st, id, name, retired)
			for _, si := range rng.Perm(len(subjects))[:rng.Intn(4)] {
				count := rng.Intn(11)
				for j := 0; j < count; j++ {
					payload := pool[rng.Intn(len(pool))]
					received := fmtTime(t0.Add(time.Duration(rng.Intn(8)) * time.Second))
					measured := fmtTime(t0.Add(-time.Hour + time.Duration(rng.Intn(20))*time.Second))
					kind := "credential"
					if rng.Intn(5) == 0 {
						kind = "cli_tool"
					}
					insertCredHistoryObservation(t, st, fmt.Sprintf("r%03d-%d", r, n), id, subjects[si], kind, measured, received, payload)
					n++
				}
			}
		}
		instants := []time.Time{t0.Add(-time.Second)}
		for i := 0; i < 3; i++ {
			instants = append(instants, t0.Add(time.Duration(rng.Intn(8))*time.Second))
		}
		instants = append(instants, t0.Add(7*time.Second), t0.Add(8*time.Second))
		for _, at := range instants {
			want, we := credHistoryRows(t, st, credRefreshHistoryReferenceSQL, fmtTime(at), 7)
			got, ge := credHistoryRows(t, st, credRefreshHistorySQL, fmtTime(at), 7)
			if we != nil || ge != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("round %d instant %s: reference error %v, query error %v; got %v; want %v", r, at, we, ge, got, want)
			}
			full, err := credHistoryRows(t, st, credRefreshHistorySQL, fmtTime(at), 8)
			if err != nil {
				t.Fatalf("round %d instant %s: %v; got %v; want %v", r, at, err, got, want)
			}
			for _, row := range full {
				if !strings.HasSuffix(row, "|int64:0") {
					t.Fatalf("round %d instant %s: invalid row %s; got %v; want %v", r, at, row, got, want)
				}
			}
			actual, ae := st.credRefreshHistory(at)
			expected, ee := referenceCredRefreshHistory(t, st, at)
			if ae != nil || ee != nil || !reflect.DeepEqual(actual, expected) {
				t.Fatalf("round %d instant %s: map errors %v, %v; actual %v; expected %v; got %v; want %v", r, at, ae, ee, actual, expected, got, want)
			}
			last = want
		}
	}
	if len(last) < credRefreshHistoryRounds {
		t.Fatalf("last reference result has %d rows, want at least %d", len(last), credRefreshHistoryRounds)
	}
}

func TestCredRefreshHistoryTextInstants(t *testing.T) {
	st := newTestStore(t)
	insertCredHistoryMachine(t, st, "m1", "one", nil)
	for i, payload := range []string{`{"file_mtime":"a"}`, `{"file_mtime":"b"}`, `{}`} {
		at := fmt.Sprintf("2026-11-10T00:00:%02dZ", i)
		insertCredHistoryObservation(t, st, fmt.Sprint(i), "m1", "claude", "credential", at, at, payload)
	}
	for _, at := range []string{"", "2026", "2026-11-10T00:00:01Z", "2026-11-10t00:00:01z", "2026-11-10T00:00:01+00:00", "zzzz", "9999-12-31T23:59:59Z"} {
		want, we := credHistoryRows(t, st, credRefreshHistoryReferenceSQL, at, 7)
		got, ge := credHistoryRows(t, st, credRefreshHistorySQL, at, 7)
		if we != nil || ge != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("instant %q: errors %v, %v; got %v; want %v", at, we, ge, got, want)
		}
	}
}

// Numerically equal file times written in different JSON number forms are one
// value. Which form SQLite reports for that value is not defined, so the two
// statements may differ there; credRefreshHistory maps every value that is not
// a timestamp to no file time, so its result is the same.
func TestCredRefreshHistoryNumericFileTimes(t *testing.T) {
	st := newTestStore(t)
	insertCredHistoryMachine(t, st, "m1", "one", nil)
	observations := []struct {
		id, subject, measured, payload string
	}{
		{"if1", "s1", "2026-11-13T00:00:02Z", `{"file_mtime":1}`},
		{"if2", "s1", "2026-11-13T00:00:01Z", `{"file_mtime":1.0}`},
		{"if3", "s2", "2026-11-13T00:00:02Z", `{"file_mtime":1.0}`},
		{"if4", "s2", "2026-11-13T00:00:01Z", `{"file_mtime":1}`},
		{"if5", "s3", "2026-11-13T00:00:02Z", `{"file_mtime":0}`},
		{"if6", "s3", "2026-11-13T00:00:01Z", `{"file_mtime":0.0}`},
		{"if7", "s4", "2026-11-13T00:00:02Z", `{"file_mtime":-0.0}`},
		{"if8", "s4", "2026-11-13T00:00:01Z", `{"file_mtime":0}`},
		{"if9", "s5", "2026-11-13T00:00:02Z", `{"file_mtime":true}`},
		{"if10", "s5", "2026-11-13T00:00:01Z", `{"file_mtime":1.0}`},
	}
	for _, o := range observations {
		insertCredHistoryObservation(t, st, o.id, "m1", o.subject, "credential", o.measured, "2026-11-13T00:00:00Z", o.payload)
	}
	firstSeen := time.Date(2026, 11, 13, 0, 0, 1, 0, time.UTC)
	for _, at := range []time.Time{
		time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC),
		firstSeen,
		time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		got, err := st.credRefreshHistory(at)
		want, referenceErr := referenceCredRefreshHistory(t, st, at)
		if err != nil || referenceErr != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("instant %s subject all: errors %v, %v; got %v; want %v", at, err, referenceErr, got, want)
		}
		if len(got) != 1 || len(got["m1"]) != 5 {
			t.Fatalf("instant %s subject all: got %v, want machine m1 with five subjects", at, got)
		}
		for _, subject := range []string{"s1", "s2", "s3", "s4", "s5"} {
			h, ok := got["m1"][subject]
			if !ok || h.DisplayName != "one" || h.Refreshes != 0 || h.FileMTime != nil || h.Retired || !h.FirstSeen.Equal(firstSeen) {
				t.Fatalf("instant %s subject %s: got %+v, present %t", at, subject, h, ok)
			}
		}
		for _, query := range []struct{ name, sql string }{
			{"reference", credRefreshHistoryReferenceSQL},
			{"history", credRefreshHistorySQL},
		} {
			rows, err := credHistoryRows(t, st, query.sql, fmtTime(at), 7)
			if err != nil || len(rows) != 5 {
				t.Fatalf("instant %s subject all: %s rows %v, error %v", at, query.name, rows, err)
			}
			for _, row := range rows {
				columns := strings.Split(row, "|")
				if columns[3] != "int64:1" {
					t.Fatalf("instant %s subject %s: %s row %s", at, columns[2], query.name, row)
				}
			}
		}
	}
}

func checkCredHistoryIntegrity(t *testing.T, st *Store) {
	t.Helper()
	rows, err := st.DB().Query(`PRAGMA integrity_check`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var results []string
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			t.Fatal(err)
		}
		results = append(results, result)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(results, []string{"ok"}) {
		t.Fatalf("integrity_check: %v", results)
	}
}

func TestCredRefreshHistoryReportsUnreadablePayload(t *testing.T) {
	cases := []struct {
		name, payload  string
		referenceFails bool
	}{
		{"open brace", "{", true}, {"empty", "", true}, {"space", " ", true}, {"truncated literal", "nul", true}, {"truncated member", `{"file_mtime":`, true}, {"unquoted key", `{file_mtime:'x'}`, false}, {"trailing comma", `{"file_mtime":"x",}`, false},
	}
	setup := func(t *testing.T, payload string, retired any, kind string) *Store {
		st := newTestStore(t)
		insertCredHistoryMachine(t, st, "m1", "one", retired)
		for i, p := range []string{`{"file_mtime":"2026-11-01T00:00:00Z"}`, payload, `{"file_mtime":"2026-11-02T00:00:00Z"}`} {
			at := fmt.Sprintf("2026-11-10T00:00:%02dZ", i*10)
			k := "credential"
			if i == 1 {
				k = kind
			}
			insertCredHistoryObservation(t, st, fmt.Sprint(i), "m1", "claude", k, at, at, p)
		}
		return st
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := setup(t, tc.payload, nil, "credential")
			at := parseTime("2026-11-10T00:00:05Z")
			out, err := st.credRefreshHistory(at)
			want, we := referenceCredRefreshHistory(t, st, at)
			if err != nil || we != nil || out["m1"]["claude"].Refreshes != 0 || !reflect.DeepEqual(out, want) {
				t.Fatalf("before invalid payload: errors %v, %v; got %v; want %v", err, we, out, want)
			}
			for _, at := range []string{"2026-11-10T00:00:10Z", "2026-11-10T00:00:30Z"} {
				if _, err := st.credRefreshHistory(parseTime(at)); !errors.Is(err, errCredentialPayloadInvalid) {
					t.Fatalf("instant %s: got %v, want invalid payload error", at, err)
				}
			}
			if _, err := credHistoryRows(t, st, credRefreshHistoryReferenceSQL, "2026-11-10T00:00:30Z", 7); (err != nil) != tc.referenceFails {
				t.Fatalf("reference error %v, want failure %t", err, tc.referenceFails)
			}
			checkCredHistoryIntegrity(t, st)
		})
	}
	t.Run("retired machine", func(t *testing.T) {
		st := setup(t, "{", "2026-11-01T00:00:00Z", "credential")
		if _, err := st.credRefreshHistory(parseTime("2026-11-10T00:00:30Z")); !errors.Is(err, errCredentialPayloadInvalid) {
			t.Fatalf("got %v, want invalid payload error", err)
		}
	})
	t.Run("other kind", func(t *testing.T) {
		st := setup(t, "{", nil, "cli_tool")
		out, err := st.credRefreshHistory(parseTime("2026-11-10T00:00:30Z"))
		if err != nil || out["m1"]["claude"].Refreshes != 1 {
			t.Fatalf("got %v, error %v; want one refresh", out, err)
		}
	})
}

func TestCredRefreshHistoryPlan(t *testing.T) {
	st := newTestStore(t)
	plan := explainChangeReadPlan(t, st, credRefreshHistorySQL, "2026-11-14T00:00:00Z")
	var got []string
	temp := 0
	for _, entry := range strings.Split(plan, "; ") {
		for _, prefix := range []string{"SEARCH o ", "SCAN o ", "SEARCH h ", "SCAN h "} {
			if strings.HasPrefix(entry, prefix) {
				got = append(got, entry)
			}
		}
		if strings.Contains(entry, "ORDER BY") {
			t.Fatalf("unexpected ORDER BY: %s", plan)
		}
		if strings.Contains(entry, "TEMP B-TREE") {
			temp++
			if entry != "USE TEMP B-TREE FOR GROUP BY" {
				t.Fatalf("unexpected temporary tree: %s", plan)
			}
		}
	}
	want := []string{
		"SEARCH o USING COVERING INDEX ix_observed_credential_mtime (machine_id=?)",
		"SEARCH o USING COVERING INDEX ix_observed_credential_mtime (machine_id=? AND subject>?)",
		"SEARCH o USING INDEX ix_observed_credential_mtime (machine_id=? AND subject=?)",
		"SEARCH o USING INDEX ix_observed_credential_mtime (machine_id=? AND subject=? AND <expr>>?)",
		"SEARCH h USING COVERING INDEX ix_observed_changes (kind=?)",
		"SEARCH o USING INDEX ix_observed_credential_mtime (machine_id=? AND subject=? AND <expr>=?)",
		"SEARCH o USING INDEX ix_observed_recent (machine_id=? AND kind=? AND subject=?)",
	}
	if !reflect.DeepEqual(got, want) || temp != 1 {
		t.Fatalf("unexpected plan: %s", plan)
	}
}

func TestCredRefreshHistoryCostFollowsDistinctFileTimes(t *testing.T) {
	if testing.Short() {
		t.Skip("cost test")
	}
	st := newTestStore(t)
	epoch := int64(1790812800)
	fallback := false
	var first string
	if err := st.DB().QueryRow(`SELECT strftime('%Y-%m-%dT%H:%M:%SZ', 1790812800 + 0, 'unixepoch')`).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first != "2026-10-01T00:00:00Z" {
		fallback = true
		epoch = time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix()
	}
	if err := st.DB().QueryRow(`SELECT strftime('%Y-%m-%dT%H:%M:%SZ', ? + 0, 'unixepoch')`, epoch).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if first != "2026-10-01T00:00:00Z" {
		t.Fatalf("epoch gives %q", first)
	}
	for m := 0; m < 4; m++ {
		id := fmt.Sprintf("m%d", m)
		insertCredHistoryMachine(t, st, id, id, nil)
		for _, subject := range []string{"claude", "codex"} {
			query := `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 4999)
INSERT INTO observed_state(observation_id,machine_id,measured_at,received_at,kind,subject,payload,source)
SELECT ? || '-' || i, ?, strftime('%Y-%m-%dT%H:%M:%SZ', 1790812800 + i, 'unixepoch'), strftime('%Y-%m-%dT%H:%M:%SZ', 1790812800 + i, 'unixepoch'), 'credential', ?, json_object('file_mtime', 'v' || (i % 20)), 'agent_measurement' FROM n`
			args := []any{id + "-" + subject, id, subject}
			if fallback {
				query = strings.ReplaceAll(query, "1790812800 + i", "@epoch + i")
				args = append(args, sql.Named("epoch", epoch))
			}
			if _, err := st.DB().Exec(query, args...); err != nil {
				t.Fatal(err)
			}
		}
	}
	measure := func(query, at string) ([]string, time.Duration) {
		var best time.Duration
		var result []string
		for i := 0; i < 3; i++ {
			start := time.Now()
			rows, err := credHistoryRows(t, st, query, at, 7)
			elapsed := time.Since(start)
			if err != nil {
				t.Fatal(err)
			}
			if i == 0 || elapsed < best {
				best = elapsed
				result = rows
			}
		}
		return result, best
	}
	instants := []string{"2026-12-01T00:00:00Z", fmtTime(time.Unix(epoch+2500, 0).UTC())}
	var durations [2][2]time.Duration
	for i, at := range instants {
		want, oldTime := measure(credRefreshHistoryReferenceSQL, at)
		got, newTime := measure(credRefreshHistorySQL, at)
		durations[i] = [2]time.Duration{oldTime, newTime}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("instant %s: got %v; want %v", at, got, want)
		}
		if i == 0 {
			if len(got) != 8 {
				t.Fatalf("got %d groups, want 8", len(got))
			}
			for _, row := range got {
				if strings.Split(row, "|")[3] != "int64:20" {
					t.Fatalf("expected 20 distinct times: %s", row)
				}
			}
		}
	}
	t.Logf("instant A: reference=%s new=%s; instant B: reference=%s new=%s", durations[0][0], durations[0][1], durations[1][0], durations[1][1])
	for i, d := range durations {
		if d[0] < 5*d[1] {
			t.Fatalf("instant %s: reference %s is less than five times new %s", instants[i], d[0], d[1])
		}
	}
}

func checkCredentialMTimeIndex(t *testing.T, st *Store) {
	t.Helper()
	var count int
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, credentialMTimeIndex).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("index count %d, want 1", count)
	}
}

func TestCredentialMTimeIndexMatchesStatementKey(t *testing.T) {
	key := "ON observed_state (machine_id, subject, " + strings.ReplaceAll(credentialMTimeKey, "o.payload", "payload") + ", received_at)"
	if !strings.Contains(schemaSQL, key) {
		t.Fatalf("schema does not contain %s", key)
	}
	path := filepath.Join(t.TempDir(), "hub.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	checkCredentialMTimeIndex(t, st)
	closeCheckpointedLedger(t, st, path)
	if err := ValidateExistingLedger(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBuildsCredentialMTimeIndexOnExistingLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	insertCredHistoryMachine(t, st, "m1", "one", nil)
	for i, payload := range []any{`{"file_mtime":"a"}`, `{`, `{"file_mtime":"b"}`, []byte("{\"file_mtime\":\"c\"}")} {
		at := fmt.Sprintf("2026-11-10T00:00:%02dZ", i*10)
		insertCredHistoryObservation(t, st, fmt.Sprint(i), "m1", "claude", "credential", at, at, payload)
	}
	if _, err := st.DB().Exec(`DROP INDEX ix_observed_credential_mtime`); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	checkCredentialMTimeIndex(t, st)
	checkCredHistoryIntegrity(t, st)
	out, err := st.credRefreshHistory(parseTime("2026-11-10T00:00:05Z"))
	if err != nil || out["m1"]["claude"].Refreshes != 0 {
		t.Fatalf("got %v, error %v; want zero refreshes", out, err)
	}
	if _, err := st.credRefreshHistory(parseTime("2026-11-10T00:00:15Z")); !errors.Is(err, errCredentialPayloadInvalid) {
		t.Fatalf("got %v, want invalid payload error", err)
	}
}
