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

const deadSignalCheckinsReferenceSQL = `
SELECT t.machine_id, COALESCE(m.display_name, t.machine_id),
       COUNT(*), COUNT(t.%[1]s), COUNT(DISTINCT t.%[1]s)
  FROM machine_checkins t LEFT JOIN machine_registry m ON m.machine_id = t.machine_id
 WHERE t.received_at >= ? AND m.retired_at IS NULL
 GROUP BY t.machine_id
 ORDER BY 2`

const agentRunsReferenceSQL = `
SELECT c.machine_id, c.agent_started_at, COUNT(*), MIN(c.received_at), MAX(c.received_at)
  FROM machine_checkins c
  LEFT JOIN machine_registry m ON m.machine_id = c.machine_id
 WHERE c.received_at >= ?
   AND c.agent_started_at IS NOT NULL AND c.agent_started_at != ''
   AND m.retired_at IS NULL
 GROUP BY c.machine_id, c.agent_started_at
 ORDER BY c.machine_id ASC, MIN(c.received_at) ASC`

const machineComplianceStatesReferenceSQL = `
SELECT m.machine_id, m.display_name, COALESCE(m.channel,''),
       c.received_at, c.agent_version, c.disk_free_bytes, c.disk_total_bytes,
       c.jobs_enabled, c.settings_digest
  FROM machine_registry m
  LEFT JOIN (SELECT machine_id, received_at, agent_version, disk_free_bytes, disk_total_bytes,
                    jobs_enabled, settings_digest,
                    ROW_NUMBER() OVER (PARTITION BY machine_id ORDER BY received_at DESC, sent_at DESC) AS rn
               FROM machine_checkins) c
    ON c.machine_id = m.machine_id AND c.rn = 1
 WHERE m.retired_at IS NULL
 ORDER BY m.display_name`

const oldestObservationReferenceSQL = `SELECT MIN(measured_at) FROM observed_state WHERE machine_id = ?`

const latestMachineJobsEnabledReferenceSQL = `SELECT jobs_enabled,received_at,rowid FROM machine_checkins WHERE machine_id=?`

func readRows(t *testing.T, st *Store, query string, args ...any) []string {
	t.Helper()
	rows, err := st.DB().Query(query, args...)
	if err != nil {
		t.Fatalf("query %s: %v", query, err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("query %s: %v", query, err)
	}
	out := []string{}
	for rows.Next() {
		values := make([]any, len(columns))
		targets := make([]any, len(columns))
		for i := range values {
			targets[i] = &values[i]
		}
		if err := rows.Scan(targets...); err != nil {
			t.Fatalf("query %s: %v", query, err)
		}
		parts := make([]string, len(values))
		for i, value := range values {
			parts[i] = fmt.Sprintf("%T:%v", value, value)
		}
		out = append(out, strings.Join(parts, "|"))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("query %s: %v", query, err)
	}
	return out
}

func sortedCopy(rows []string) []string {
	out := append([]string{}, rows...)
	sort.Strings(out)
	return out
}

func checkinReadExec(t *testing.T, st *Store, query string, args ...any) {
	t.Helper()
	if _, err := st.DB().Exec(query, args...); err != nil {
		t.Fatalf("query %s: %v", query, err)
	}
}

func checkinReadMachine(t *testing.T, st *Store, id, name string, retired any) {
	t.Helper()
	checkinReadExec(t, st, "INSERT INTO machine_registry (machine_id, display_name, created_at, retired_at) VALUES (?,?,?,?)", id, name, "2026-10-01T00:00:00Z", retired)
}

func checkinReadCompare(t *testing.T, round int, name string, arg any, got, want []string, order ...int) {
	t.Helper()
	fail := func() { t.Fatalf("round %d statement %s argument %v: got %v; want %v", round, name, arg, got, want) }
	if !reflect.DeepEqual(sortedCopy(got), sortedCopy(want)) {
		fail()
	}
	for i := 1; i < len(got); i++ {
		a, b := strings.Split(got[i-1], "|"), strings.Split(got[i], "|")
		for _, col := range order {
			if a[col] < b[col] {
				break
			}
			if a[col] > b[col] {
				fail()
			}
		}
	}
}

func TestCheckinWindowReadsMatchReference(t *testing.T) {
	st := newTestStore(t)
	rng := rand.New(rand.NewSource(20261114))
	t0 := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	var ids, lastCompliance []string
	pick := func(values ...any) any { return values[rng.Intn(len(values))] }
	for r := 0; r < 60; r++ {
		count := 1 + rng.Intn(3)
		for _, suffix := range []string{"a", "a1", "b"}[:count] {
			id := fmt.Sprintf("r%03d-%s", r, suffix)
			ids = append(ids, id)
			name := pick("", "alpha", fmt.Sprintf("name-%d-%s", r, suffix)).(string)
			var retired any
			if rng.Intn(4) == 0 {
				retired = "2026-11-01T00:00:00Z"
			}
			checkinReadMachine(t, st, id, name, retired)
			k := rng.Intn(13)
			perm := rng.Perm(k)
			for j := 0; j < k; j++ {
				sent := fmtTime(t0.Add(-time.Hour + time.Duration(perm[j])*time.Second))
				received := fmtTime(t0.Add(time.Duration(rng.Intn(10)) * time.Second))
				started := pick(nil, "", "2026-11-09T00:00:00Z", "2026-11-09T01:00:00Z", "2026-11-09T02:00:00Z")
				age, skew := pick(nil, rng.Intn(3)), pick(nil, rng.Intn(3))
				version := pick(nil, "1.2.3", "1.2.4")
				free, total := pick(nil, rng.Int63n(1000)), pick(nil, rng.Int63n(1000))
				jobs, digest := pick(nil, 0, 1), pick(nil, "d1", "d2")
				checkinReadExec(t, st, "INSERT INTO machine_checkins(machine_id,sent_at,received_at,agent_version,agent_started_at,disk_free_bytes,disk_total_bytes,jobs_enabled,observation_age_seconds,clock_skew_seconds,settings_digest) VALUES(?,?,?,?,?,?,?,?,?,?,?)", id, sent, received, version, started, free, total, jobs, age, skew, digest)
			}
		}
		for _, offset := range []int{-1, rng.Intn(10), rng.Intn(10), 9, 10} {
			since := fmtTime(t0.Add(time.Duration(offset) * time.Second))
			for _, column := range []string{"observation_age_seconds", "agent_started_at", "clock_skew_seconds"} {
				want := readRows(t, st, fmt.Sprintf(deadSignalCheckinsReferenceSQL, column), since)
				got := readRows(t, st, fmt.Sprintf(deadSignalCheckinsSQL, column), since)
				checkinReadCompare(t, r, "deadSignalCheckinsSQL", []string{column, since}, got, want, 1)
			}
			want := readRows(t, st, agentRunsReferenceSQL, since)
			got := readRows(t, st, agentRunsSQL, since)
			checkinReadCompare(t, r, "agentRunsSQL", since, got, want, 0, 3)
		}
		want := readRows(t, st, machineComplianceStatesReferenceSQL)
		lastCompliance = readRows(t, st, machineComplianceStatesSQL)
		checkinReadCompare(t, r, "machineComplianceStatesSQL", nil, lastCompliance, want, 1)
		for _, id := range append(append([]string{}, ids...), "missing") {
			checkinReadCompare(t, r, "latestMachineJobsEnabledSQL", id, readRows(t, st, latestMachineJobsEnabledSQL, id), readRows(t, st, latestMachineJobsEnabledReferenceSQL, id))
		}
	}
	runs := readRows(t, st, agentRunsReferenceSQL, fmtTime(t0.Add(-time.Second)))
	if len(lastCompliance) < 40 || len(runs) < 60 {
		t.Fatalf("round 59 statement compliance/agent runs argument %s: got %v; want at least 40 compliance and 60 agent rows; agent rows %v", fmtTime(t0.Add(-time.Second)), lastCompliance, runs)
	}
}

func TestCheckinWindowReadsWithUnregisteredMachine(t *testing.T) {
	st := newTestStore(t)
	checkinReadMachine(t, st, "m1", "one", nil)
	insert := func(id string, count int) {
		for i := 0; i < count; i++ {
			var started any = "2026-11-09T00:00:00Z"
			if id == "ghost" && i == 0 {
				started = nil
			}
			checkinReadExec(t, st, "INSERT INTO machine_checkins(machine_id,sent_at,received_at,agent_started_at,observation_age_seconds,clock_skew_seconds) VALUES(?,?,?,?,?,?)", id, fmt.Sprintf("2026-11-10T00:00:0%dZ", i), "2026-11-10T00:00:00Z", started, i, i)
		}
	}
	insert("m1", 2)
	checkinReadExec(t, st, "PRAGMA foreign_keys=OFF")
	insert("ghost", 3)
	checkinReadExec(t, st, "PRAGMA foreign_keys=ON")
	since := "2026-11-09T00:00:00Z"
	for _, col := range []string{"observation_age_seconds", "agent_started_at", "clock_skew_seconds"} {
		got, want := readRows(t, st, fmt.Sprintf(deadSignalCheckinsSQL, col), since), readRows(t, st, fmt.Sprintf(deadSignalCheckinsReferenceSQL, col), since)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: got %v; want %v", col, got, want)
		}
		found := false
		for _, row := range got {
			parts := strings.Split(row, "|")
			if parts[0] == "string:ghost" && parts[1] == "string:ghost" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: missing ghost row in %v", col, got)
		}
	}
	got, want := readRows(t, st, agentRunsSQL, since), readRows(t, st, agentRunsReferenceSQL, since)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("agent runs: got %v; want %v", got, want)
	}
}

func TestOldestObservationMatchesReference(t *testing.T) {
	st := newTestStore(t)
	rng := rand.New(rand.NewSource(20261114))
	t0 := time.Date(2026, 11, 10, 0, 0, 0, 0, time.UTC)
	ids := []string{"missing"}
	for m := 0; m < 40; m++ {
		id := fmt.Sprintf("m%02d", m)
		ids = append(ids, id)
		checkinReadMachine(t, st, id, id, nil)
		if m == 0 {
			continue
		}
		n := 1 + rng.Intn(40)
		for j := 0; j < n; j++ {
			kind := []string{"credential", "cli_tool", "systemd", "a"}[rng.Intn(4)]
			subject := []string{"", "claude", "claude-2", "unit.service"}[rng.Intn(4)]
			measured := []string{"", "zzz", fmtTime(t0.Add(time.Duration(rng.Intn(50)-25) * time.Hour))}[rng.Intn(3)]
			checkinReadExec(t, st, "INSERT INTO observed_state(observation_id,machine_id,kind,subject,measured_at,received_at,payload,source) VALUES(?,?,?,?,?,?,?,?)", fmt.Sprintf("%s-%d", id, j), id, kind, subject, measured, fmtTime(t0), "{}", "agent_measurement")
		}
	}
	for _, id := range ids {
		got, want := readRows(t, st, oldestObservationSQL, id), readRows(t, st, oldestObservationReferenceSQL, id)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("machine %s: got %v; want %v", id, got, want)
		}
	}
	if _, ok, err := st.OldestObservation("m00"); ok || err != nil {
		t.Fatalf("empty machine: ok=%v error=%v", ok, err)
	}
}

func TestLatestMachineJobsEnabledFailsClosedOnUnparsableHubTime(t *testing.T) {
	st := newTestStore(t)
	checkinReadMachine(t, st, "m1", "one", nil)
	for i, received := range []string{"zzz", "2026-11-10T00:01:00Z", "2026-11-10T00:02:00Z"} {
		checkinReadExec(t, st, "INSERT INTO machine_checkins(machine_id,sent_at,received_at,jobs_enabled) VALUES(?,?,?,1)", "m1", fmt.Sprintf("2026-11-10T00:0%d:00Z", i), received)
	}
	if _, err := latestMachineJobsEnabled(st.DB(), "m1"); !errors.Is(err, errMachineJobsEnabledProjectionInvalid) {
		t.Fatalf("invalid Hub time: %v", err)
	}
	checkinReadExec(t, st, "DELETE FROM machine_checkins WHERE received_at='zzz'")
	enabled, err := latestMachineJobsEnabled(st.DB(), "m1")
	if err != nil || enabled == nil || !*enabled {
		t.Fatalf("valid Hub times: enabled=%v error=%v", enabled, err)
	}
}

func TestCheckinWindowReadPlans(t *testing.T) {
	st := newTestStore(t)
	cases := []struct {
		name, query    string
		args           []any
		prefixes, want []string
	}{
		{"dead signal", fmt.Sprintf(deadSignalCheckinsSQL, "observation_age_seconds"), []any{"2026-11-14T00:00:00Z"}, []string{"SEARCH t ", "SCAN t "}, []string{
			"SCAN t USING COVERING INDEX ix_checkin_recent",
			"SEARCH t USING COVERING INDEX ix_checkin_recent (machine_id>?)",
			"SEARCH t USING INDEX ix_checkin_recent (machine_id=? AND received_at>?)"}},
		{"agent runs", agentRunsSQL, []any{"2026-11-14T00:00:00Z"}, []string{"SEARCH t ", "SCAN t ", "SEARCH c ", "SCAN c "}, []string{
			"SCAN t USING COVERING INDEX ix_checkin_recent",
			"SEARCH t USING COVERING INDEX ix_checkin_recent (machine_id>?)",
			"SEARCH c USING INDEX ix_checkin_recent (machine_id=? AND received_at>?)"}},
		{"compliance", machineComplianceStatesSQL, nil, []string{"SEARCH c ", "SCAN c ", "SEARCH x ", "SCAN x "}, []string{
			"SEARCH c USING INTEGER PRIMARY KEY (rowid=?) LEFT-JOIN",
			"SEARCH x USING INDEX ix_checkin_recent (machine_id=?)"}},
		{"oldest", oldestObservationSQL, []any{"m1"}, []string{"SEARCH o ", "SCAN o "}, []string{
			"SEARCH o USING COVERING INDEX ix_observed_recent (machine_id=?)",
			"SEARCH o USING COVERING INDEX ix_observed_recent (machine_id=? AND kind>?)",
			"SEARCH o USING COVERING INDEX ix_observed_recent (machine_id=? AND kind=?)",
			"SEARCH o USING COVERING INDEX ix_observed_recent (machine_id=? AND kind=? AND subject>?)",
			"SEARCH o USING COVERING INDEX ix_observed_recent (machine_id=? AND kind=? AND subject=?)"}},
	}
	for _, tc := range cases {
		plan := explainChangeReadPlan(t, st, tc.query, tc.args...)
		var got []string
		for _, entry := range strings.Split(plan, "; ") {
			for _, prefix := range tc.prefixes {
				if strings.HasPrefix(entry, prefix) {
					got = append(got, entry)
					break
				}
			}
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Fatalf("%s plan: %s; got %v; want %v", tc.name, plan, got, tc.want)
		}
		if tc.name == "oldest" && strings.Contains(plan, "TEMP B-TREE") {
			t.Fatalf("oldest plan: %s", plan)
		}
	}
	plan := explainChangeReadPlan(t, st, latestMachineJobsEnabledSQL, "m1")
	if plan != "SEARCH machine_checkins USING COVERING INDEX ix_checkin_jobs_enabled (machine_id=?)" {
		t.Fatalf("jobs enabled plan: %s", plan)
	}
}

func bestCheckinRead(t *testing.T, st *Store, query string, args ...any) ([]string, time.Duration) {
	t.Helper()
	var best time.Duration
	var rows []string
	for i := 0; i < 3; i++ {
		start := time.Now()
		got := readRows(t, st, query, args...)
		elapsed := time.Since(start)
		if i == 0 || elapsed < best {
			best = elapsed
			rows = got
		}
	}
	return rows, best
}

func TestMachineComplianceStatesCostFollowsMachines(t *testing.T) {
	if testing.Short() {
		t.Skip("cost test")
	}
	st := newTestStore(t)
	for m := 0; m < 6; m++ {
		id := fmt.Sprintf("m%d", m)
		checkinReadMachine(t, st, id, fmt.Sprintf("name-%d", m), nil)
		checkinReadExec(t, st, `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 7999) INSERT INTO machine_checkins(machine_id,sent_at,received_at,agent_version,jobs_enabled) SELECT ?1, strftime('%Y-%m-%dT%H:%M:%SZ', ?2 + i*60, 'unixepoch'), strftime('%Y-%m-%dT%H:%M:%SZ', ?2 + i*60, 'unixepoch'), 'v' || i, i % 2 FROM n`, id, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix())
	}
	want, referenceDuration := bestCheckinRead(t, st, machineComplianceStatesReferenceSQL)
	got, newDuration := bestCheckinRead(t, st, machineComplianceStatesSQL)
	t.Logf("reference duration=%s new duration=%s", referenceDuration, newDuration)
	if !reflect.DeepEqual(got, want) || len(got) != 6 {
		t.Fatalf("got %v; want %v (6 rows)", got, want)
	}
	for _, row := range got {
		if strings.Split(row, "|")[4] != "string:v7999" {
			t.Fatalf("latest version: %s", row)
		}
	}
	if referenceDuration < 5*newDuration {
		t.Fatalf("reference duration %s < 5 * new duration %s", referenceDuration, newDuration)
	}
}

func TestOldestObservationCostFollowsSubjects(t *testing.T) {
	if testing.Short() {
		t.Skip("cost test")
	}
	st := newTestStore(t)
	checkinReadMachine(t, st, "m1", "one", nil)
	for _, kind := range []string{"a", "b", "c"} {
		for s := 0; s < 4; s++ {
			subject := fmt.Sprintf("s%d", s)
			checkinReadExec(t, st, `WITH RECURSIVE n(i) AS (SELECT 0 UNION ALL SELECT i+1 FROM n WHERE i < 3999)
INSERT INTO observed_state(observation_id,machine_id,kind,subject,measured_at,received_at,payload,source)
SELECT ?1 || '-' || ?2 || '-' || i, 'm1', ?1, ?2,
strftime('%Y-%m-%dT%H:%M:%SZ', ?3 + i*60, 'unixepoch'),
strftime('%Y-%m-%dT%H:%M:%SZ', ?3 + i*60, 'unixepoch'), '{}', 'agent_measurement' FROM n`, kind, subject, time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).Unix())
		}
	}
	want, referenceDuration := bestCheckinRead(t, st, oldestObservationReferenceSQL, "m1")
	got, newDuration := bestCheckinRead(t, st, oldestObservationSQL, "m1")
	t.Logf("reference duration=%s new duration=%s", referenceDuration, newDuration)
	expected := []string{"string:2026-10-01T00:00:00Z"}
	if !reflect.DeepEqual(got, expected) || !reflect.DeepEqual(want, expected) {
		t.Fatalf("got %v; reference %v; want %v", got, want, expected)
	}
	if referenceDuration < 5*newDuration {
		t.Fatalf("reference duration %s < 5 * new duration %s", referenceDuration, newDuration)
	}
}

func TestCheckinJobsEnabledIndexIsPartOfAValidLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	got := readRows(t, st, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='ix_checkin_jobs_enabled'")
	if !reflect.DeepEqual(got, []string{"int64:1"}) {
		t.Fatalf("index count: %v", got)
	}
	closeCheckpointedLedger(t, st, path)
	if err := ValidateExistingLedger(path); err != nil {
		t.Fatal(err)
	}
}

func TestOpenBuildsCheckinJobsEnabledIndexOnExistingLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	checkinReadMachine(t, st, "m1", "one", nil)
	for i, jobs := range []any{0, nil, 1} {
		at := fmt.Sprintf("2026-11-10T00:0%d:00Z", i)
		checkinReadExec(t, st, "INSERT INTO machine_checkins(machine_id,sent_at,received_at,jobs_enabled) VALUES(?,?,?,?)", "m1", at, at, jobs)
	}
	checkinReadExec(t, st, "DROP INDEX ix_checkin_jobs_enabled")
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	st, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	got := readRows(t, st, "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='ix_checkin_jobs_enabled'")
	if !reflect.DeepEqual(got, []string{"int64:1"}) {
		t.Fatalf("index count: %v", got)
	}
	enabled, err := latestMachineJobsEnabled(st.DB(), "m1")
	if err != nil || enabled == nil || !*enabled {
		t.Fatalf("enabled=%v error=%v", enabled, err)
	}
	got = readRows(t, st, "PRAGMA integrity_check")
	if !reflect.DeepEqual(got, []string{"string:ok"}) {
		t.Fatalf("integrity check: %v", got)
	}
}

func TestOpenBuildsCheckinJobsEnabledIndexOnHistoricalLedger(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.db")
	createManifestLedger(t, path, ledgerFixtureOptions{occupancyColumns: legacyOccupancyFixtureColumns})
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	const columnCount = `SELECT COUNT(*) FROM pragma_table_info('machine_checkins') WHERE name = 'jobs_enabled'`
	var count int
	if err := db.QueryRow(columnCount).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("fixture already has jobs_enabled")
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	st, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.DB().QueryRow(columnCount).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("jobs_enabled column count=%d, want 1", count)
	}
	if err := st.DB().QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='ix_checkin_jobs_enabled'`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("index count=%d, want 1", count)
	}
	if _, err := latestMachineJobsEnabled(st.DB(), "m1"); err != nil {
		t.Fatal(err)
	}
	closeCheckpointedLedger(t, st, path)
	if err := ValidateExistingLedger(path); err != nil {
		t.Fatal(err)
	}
}

func TestCheckinWindowReadsWithSingleCheckinFirstMachine(t *testing.T) {
	st := newTestStore(t)
	checkinReadMachine(t, st, "a", "A", nil)
	checkinReadMachine(t, st, "b", "B", nil)
	for _, entry := range []struct{ id, sent string }{
		{"a", "2026-11-10T00:00:00Z"},
		{"b", "2026-11-10T00:00:00Z"},
		{"b", "2026-11-10T00:00:01Z"},
		{"b", "2026-11-10T00:00:02Z"},
	} {
		checkinReadExec(t, st, `INSERT INTO machine_checkins(machine_id,sent_at,received_at,agent_started_at,observation_age_seconds,clock_skew_seconds,agent_version) VALUES(?,?,?,?,?,?,?)`, entry.id, entry.sent, "2026-11-10T00:00:00Z", "2026-11-09T00:00:00Z", 1, 1, "1.2.3")
	}
	since := "2026-11-09T00:00:00Z"
	for _, column := range []string{"observation_age_seconds", "agent_started_at", "clock_skew_seconds"} {
		got := readRows(t, st, fmt.Sprintf(deadSignalCheckinsSQL, column), since)
		want := readRows(t, st, fmt.Sprintf(deadSignalCheckinsReferenceSQL, column), since)
		if !reflect.DeepEqual(got, want) || len(got) != 2 || strings.Split(got[0], "|")[0] != "string:a" {
			t.Fatalf("%s: got %v; want %v, with two rows starting with a", column, got, want)
		}
	}
	got, want := readRows(t, st, agentRunsSQL, since), readRows(t, st, agentRunsReferenceSQL, since)
	if !reflect.DeepEqual(got, want) || len(got) != 2 || strings.Split(got[0], "|")[0] != "string:a" {
		t.Fatalf("agent runs: got %v; want %v, with two rows starting with a", got, want)
	}
	got, want = readRows(t, st, machineComplianceStatesSQL), readRows(t, st, machineComplianceStatesReferenceSQL)
	if !reflect.DeepEqual(got, want) || len(got) != 2 {
		t.Fatalf("compliance: got %v; want %v, with two rows", got, want)
	}
}

func TestOldestObservationWithSingleRowFirstKind(t *testing.T) {
	st := newTestStore(t)
	checkinReadMachine(t, st, "m1", "m1", nil)
	checkinReadMachine(t, st, "m2", "m2", nil)
	for _, entry := range []struct{ id, machine, kind, measured string }{
		{"o1", "m1", "a", "2026-11-01T00:00:00Z"},
		{"o2", "m1", "b", "2026-11-02T00:00:00Z"},
		{"o3", "m1", "b", "2026-11-03T00:00:00Z"},
		{"o4", "m2", "b", "2026-11-05T00:00:00Z"},
	} {
		checkinReadExec(t, st, `INSERT INTO observed_state(observation_id,machine_id,kind,subject,measured_at,received_at,payload,source) VALUES(?,?,?,?,?,?,?,?)`, entry.id, entry.machine, entry.kind, "s", entry.measured, "2026-11-10T00:00:00Z", "{}", "agent_measurement")
	}
	for _, tc := range []struct{ machine, measured string }{{"m1", "2026-11-01T00:00:00Z"}, {"m2", "2026-11-05T00:00:00Z"}} {
		want := []string{"string:" + tc.measured}
		got, reference := readRows(t, st, oldestObservationSQL, tc.machine), readRows(t, st, oldestObservationReferenceSQL, tc.machine)
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(reference, want) {
			t.Fatalf("machine %s: got %v; reference %v; want %v", tc.machine, got, reference, want)
		}
	}
}
