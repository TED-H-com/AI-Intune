package store

import (
	"context"
	"github.com/teddashh/AI-Intune/internal/errlog"
	"path/filepath"
	"testing"
	"time"
)

func TestErrorStorageIndependentWriterAndRetention(t *testing.T) {
	s := newTestStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	held, e := s.beginWrite(ctx, "held")
	if e != nil {
		t.Fatal(e)
	}
	now := s.now()
	records := []errlog.Record{{TS: now, MachineID: "a", Fingerprint: "fp", Component: "agent", Count: 2}, {TS: now.Add(time.Second), MachineID: "b", Fingerprint: "fp", Component: "agent", Count: 4}}
	if _, e = s.InsertErrors(ctx, records); e != nil {
		t.Fatal(e)
	}
	held.Rollback()
	top, e := s.TopErrors(ctx, now.Add(-time.Hour))
	if e != nil || len(top) != 1 || top[0].Count != 6 || len(top[0].Machines) != 2 {
		t.Fatalf("aggregate: %+v %v", top, e)
	}
	c, e := s.pruneErrors(now.Add(31*24*time.Hour), true)
	if e != nil || c.Deleted != 2 {
		t.Fatalf("preview: %+v %v", c, e)
	}
	c, e = s.pruneErrors(now.Add(31*24*time.Hour), false)
	if e != nil || c.Deleted != 2 {
		t.Fatalf("prune: %+v %v", c, e)
	}
	top, e = s.TopErrors(ctx, now.Add(-time.Hour))
	if e != nil || len(top) != 0 {
		t.Fatalf("retained: %+v %v", top, e)
	}
}

func TestErrorPersistenceAndFilters(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hub.db")
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	records := []errlog.Record{{TS: now, MachineID: "a", Fingerprint: "fp", Component: "agent", Count: 1}, {TS: now.Add(-time.Hour), MachineID: "b", Fingerprint: "fp2", Component: "bat", Count: 1}}
	if _, e = s.InsertErrors(context.Background(), records); e != nil {
		t.Fatal(e)
	}
	if e = s.Close(); e != nil {
		t.Fatal(e)
	}
	s, e = Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	for _, f := range []ErrorFilter{{Since: now.Add(-time.Minute)}, {Since: now.Add(-24 * time.Hour), Component: "bat"}, {Since: now.Add(-24 * time.Hour), Machine: "a"}, {Since: now.Add(-24 * time.Hour), Limit: 1}} {
		got, e := s.ListErrors(context.Background(), f)
		if e != nil || len(got) != 1 {
			t.Fatalf("filter %+v: %+v %v", f, got, e)
		}
	}
	rep, e := s.Prune(now.Add(31*24*time.Hour), DefaultRetention(), true)
	if e != nil {
		t.Fatal(e)
	}
	found := false
	for _, c := range rep.Counts {
		if c.Table == "error_records" {
			found = true
			if c.Deleted != 2 {
				t.Fatalf("preview: %+v", c)
			}
		}
	}
	if !found {
		t.Fatal("missing error retention report")
	}
	rep, e = s.Prune(now.Add(31*24*time.Hour), DefaultRetention(), false)
	if e != nil {
		t.Fatal(e)
	}
	got, e := s.ListErrors(context.Background(), ErrorFilter{Since: now.Add(-24 * time.Hour)})
	if e != nil || len(got) != 0 {
		t.Fatalf("pruned: %+v %v", got, e)
	}
}
