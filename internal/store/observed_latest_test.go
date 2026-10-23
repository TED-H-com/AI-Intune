package store

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func assertLatestEquivalent(t *testing.T, s *Store) {
	t.Helper()
	// The old MAX(received_at) query admitted ties; measured_at then insertion
	// sequence selected the winner. Compare every projected column, in both directions.
	const old = `SELECT o.machine_id,o.kind,o.subject,o.observation_id,o.measured_at,o.received_at,o.payload,o.source,o.rowid
 FROM observed_state o WHERE o.received_at=(SELECT MAX(h.received_at) FROM observed_state h WHERE h.machine_id=o.machine_id AND h.kind=o.kind AND h.subject=o.subject)
 AND o.rowid=(SELECT h.rowid FROM observed_state h WHERE h.machine_id=o.machine_id AND h.kind=o.kind AND h.subject=o.subject ORDER BY h.received_at DESC,h.measured_at DESC,h.rowid DESC LIMIT 1)`
	const current = `SELECT machine_id,kind,subject,observation_id,measured_at,received_at,payload,source,observation_sequence FROM observed_latest`
	for _, q := range []string{"SELECT COUNT(*) FROM (" + old + " EXCEPT " + current + ")", "SELECT COUNT(*) FROM (" + current + " EXCEPT " + old + ")"} {
		var n int
		if err := s.rdb.QueryRow(q).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Fatalf("projection differs: %d rows", n)
		}
	}
}

func TestObservedLatestRandomEquivalence(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC().Truncate(time.Second)
	ids := []string{mustEnroll(t, s, "latest-a", now), mustEnroll(t, s, "latest-b", now)}
	rng := rand.New(rand.NewSource(817))
	for i := 0; i < 500; i++ {
		// Independent clocks, out-of-order delivery, and deliberately frequent ties.
		_, err := s.db.Exec(`INSERT INTO observed_state VALUES(?,?,?,?,?,?,?,?)`, fmt.Sprint(i), ids[rng.Intn(2)], fmtTime(now.Add(time.Duration(rng.Intn(7))*time.Hour)), fmtTime(now.Add(time.Duration(rng.Intn(7))*time.Second)), "cli_tool", fmt.Sprint(rng.Intn(8)), fmt.Sprintf(`{"version":%d}`, i), SourceAgentMeasurement)
		if err != nil {
			t.Fatal(err)
		}
		if i%50 == 0 {
			assertLatestEquivalent(t, s)
		}
	}
	assertLatestEquivalent(t, s)
	// Simulate a pre-projection database, then repeat the resumable migration.
	if _, err := s.db.Exec("DELETE FROM observed_latest"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if err := s.backfillObservedLatest(); err != nil {
			t.Fatal(err)
		}
		assertLatestEquivalent(t, s)
	}
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = tx.Exec(`INSERT INTO observed_state VALUES('rollback',?,?,?,?,?,?,?)`, ids[0], fmtTime(now), fmtTime(now.Add(time.Hour)), "cli_tool", "0", "{}", SourceAgentMeasurement); err != nil {
		t.Fatal(err)
	}
	tx.Rollback()
	assertLatestEquivalent(t, s)
}

func TestObservationUnchangedInterval(t *testing.T) {
	for _, kind := range []string{KindCLITool, KindSystemd} {
		t.Run(kind, func(t *testing.T) {
			s := newTestStore(t)
			now := time.Now().UTC().Truncate(time.Second)
			id := mustEnroll(t, s, "interval", now)
			record := func(at time.Time, changed bool) {
				b := model.ObservationBatch{MeasuredAt: at}
				if kind == KindCLITool {
					b.CLITools = []model.CLITool{{Name: "tool", Present: changed}}
				} else {
					b.Systemd = []model.Unit{{Name: "tool", Present: changed}}
				}
				if err := s.RecordObservation(id, b, at); err != nil {
					t.Fatal(err)
				}
			}
			check := func(want int, at time.Time) {
				t.Helper()
				var n int
				var recv string
				if err := s.rdb.QueryRow("SELECT COUNT(*) FROM observed_state WHERE machine_id=? AND kind=?", id, kind).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if n != want {
					t.Fatalf("rows=%d want %d", n, want)
				}
				if err := s.rdb.QueryRow("SELECT received_at FROM observed_latest WHERE machine_id=? AND kind=?", id, kind).Scan(&recv); err != nil {
					t.Fatal(err)
				}
				if recv != fmtTime(at) {
					t.Fatalf("received=%s want %s", recv, fmtTime(at))
				}
			}
			record(now, false)
			check(1, now)
			record(now.Add(time.Minute), false)
			check(1, now)
			record(now.Add(2*time.Minute), true)
			check(2, now.Add(2*time.Minute))
			record(now.Add(32*time.Minute), true)
			check(3, now.Add(32*time.Minute))
			s.SetObservationUnchangedInterval(0)
			record(now.Add(33*time.Minute), true)
			check(4, now.Add(33*time.Minute))
			assertLatestEquivalent(t, s)
		})
	}
}

func TestObservedLatestBackfillMultipleBatches(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	id := mustEnroll(t, s, "backfill", now)
	_, err := s.db.Exec(`WITH RECURSIVE n(i) AS (VALUES(1) UNION ALL SELECT i+1 FROM n WHERE i<2005)
 INSERT INTO observed_state SELECT 'batch-'||i,?,?,?,'cli_tool','subject-'||i,'{}',? FROM n`, id, fmtTime(now), fmtTime(now), SourceAgentMeasurement)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("DELETE FROM observed_latest"); err != nil {
		t.Fatal(err)
	}
	if err = s.backfillObservedLatest(); err != nil {
		t.Fatal(err)
	}
	assertLatestEquivalent(t, s)
}

func TestObservedLatestStartupAndRetention(t *testing.T) {
	path := t.TempDir() + "/startup.db"
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	old := now.Add(-90 * 24 * time.Hour)
	id := mustEnroll(t, s, "startup", old)
	for i := 0; i < 3; i++ {
		_, err = s.db.Exec(`INSERT INTO observed_state VALUES(?,?,?,?,?,?,?,?)`, fmt.Sprint(i), id, fmtTime(old.Add(time.Duration(2-i)*time.Hour)), fmtTime(old.Add(time.Duration(i)*time.Hour)), "cli_tool", "tool", "{}", SourceAgentMeasurement)
		if err != nil {
			t.Fatal(err)
		}
	}
	// Reproduce a legacy database without the projection or trigger.
	if _, err = s.db.Exec("DROP TRIGGER observed_latest_insert; DROP TABLE observed_latest"); err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	assertLatestEquivalent(t, s)
	if _, err = s.Prune(now, DefaultRetention(), false); err != nil {
		t.Fatal(err)
	}
	assertLatestEquivalent(t, s)
	var count int
	if err = s.rdb.QueryRow("SELECT COUNT(*) FROM observed_latest").Scan(&count); err != nil || count != 1 {
		t.Fatalf("projection pruned: count=%d err=%v", count, err)
	}
	if err = s.rdb.QueryRow("SELECT COUNT(*) FROM observed_state").Scan(&count); err != nil || count != 2 {
		t.Fatalf("retention must protect both clock maxima: count=%d err=%v", count, err)
	}
}
