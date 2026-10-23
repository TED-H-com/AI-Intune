package store

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func TestPruneBatchesYieldAndCheckpoint(t *testing.T) {
	s := newTestStore(t)
	now := time.Now().UTC()
	machine := mustEnroll(t, s, "prune-batches", now.Add(-60*24*time.Hour))
	old := fmtTime(now.Add(-50 * 24 * time.Hour))
	tx, err := s.beginWrite(context.Background(), "seed")
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	for i := 0; i < 2*pruneBatchSize+1; i++ {
		if _, err := tx.Exec("INSERT INTO observed_state(observation_id,machine_id,measured_at,received_at,kind,subject,payload,source) VALUES(?,?,?,?,?,?,?,?)",
			fmt.Sprint(i), machine, old, old, "test", "test", "{}", SourceAgentMeasurement); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := tx.Exec("INSERT INTO observed_state(observation_id,machine_id,measured_at,received_at,kind,subject,payload,source) VALUES(?,?,?,?,?,?,?,?)",
		"latest", machine, fmtTime(now), fmtTime(now), "test", "test", "{}", SourceAgentMeasurement); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	// Disable auto-checkpoint so shrinking the WAL proves the explicit checkpoint ran.
	if _, err := s.db.Exec("PRAGMA wal_autocheckpoint=0"); err != nil {
		t.Fatal(err)
	}
	var dbPath string
	var seq int
	var name string
	if err := s.rdb.QueryRow("PRAGMA database_list").Scan(&seq, &name, &dbPath); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	done := make(chan error, 1)
	go func() { _, err := s.Prune(now, DefaultRetention(), false); done <- err }()
	// Observe a committed full batch, then acquire the writer during its yield.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := s.rdb.QueryRow("SELECT COUNT(*) FROM retention_log WHERE table_name='observed_state' AND rows_deleted=?", pruneBatchSize).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no full batch committed")
		}
		time.Sleep(time.Millisecond)
	}
	interactive, err := s.beginWriteInteractive(context.Background(), "prune_interleave")
	if err != nil {
		t.Fatal(err)
	}
	var remaining int
	if err := interactive.QueryRow("SELECT COUNT(*) FROM observed_state").Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if err := interactive.Commit(); err != nil {
		t.Fatal(err)
	}
	if remaining <= 1 {
		t.Fatal("prune did not yield between batches")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if time.Since(started) < 3*pruneBatchYield {
		t.Fatal("missing batch yields")
	}
	var maxBatch int
	if err := s.rdb.QueryRow("SELECT MAX(rows_deleted) FROM retention_log").Scan(&maxBatch); err != nil {
		t.Fatal(err)
	}
	if maxBatch != 1000 {
		t.Fatalf("maximum batch=%d", maxBatch)
	}
	info, err := os.Stat(dbPath + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("WAL size after checkpoint=%d", info.Size())
	}
}

func BenchmarkRecordObservation(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "bench.db"))
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	now := time.Now().UTC()
	token, err := s.CreateEnrollToken("benchmark", time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	machine, _, err := s.RedeemEnrollToken(token, model.EnrollRequest{SchemaVersion: model.SchemaVersion, EnrollToken: token, Hostname: "benchmark", OS: "linux", Arch: "amd64", UnixUser: "example-user"}, now)
	if err != nil {
		b.Fatal(err)
	}
	batch := healthyBatch(now)
	for i := 0; i < 250; i++ {
		batch.Systemd = append(batch.Systemd, model.Unit{Name: fmt.Sprintf("unit-%d.service", i)})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := s.RecordObservation(machine, batch, now); err != nil {
			b.Fatal(err)
		}
	}
}
