package store

import (
	"fmt"
	"testing"
	"time"
)

func TestOpsApprovalsFilteredNewestBeforeLimit(t *testing.T) {
	s, _, _, _ := diskPolicyFixture(t)
	machine := mustEnroll(t, s, "approval-test", s.now())
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 606; i++ {
		created := now.Add(time.Duration(i/2) * time.Nanosecond)
		if i >= 504 {
			created = created.Add(-time.Hour)
		}
		_, err := s.db.Exec(`INSERT INTO ops_approvals(id,state,actor,machine_id,operation,policy_id,policy_revision,policy_digest,item_digest,created_at,deadline) VALUES (?,'pending','admin',?,'quarantine','disk-default',1,'digest','items',?,?)`, fmt.Sprintf("approval-%04d", i), machine, created.Format(time.RFC3339Nano), created.Add(30*time.Minute).Format(time.RFC3339Nano))
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, state := range []string{"", "pending", "expired"} {
		rows, err := s.OpsApprovalsFiltered(state, machine, "quarantine", now)
		if err != nil {
			t.Fatal(err)
		}
		count, top := 500, 502
		if state == "expired" {
			count, top = 102, 604
		}
		if len(rows) != count {
			t.Fatalf("%s: got %d want %d", state, len(rows), count)
		}
		for rank, row := range rows {
			want := fmt.Sprintf("approval-%04d", top-(rank/2)*2+rank%2)
			if row.ID != want {
				t.Fatalf("%s rank %d: got %s want %s", state, rank, row.ID, want)
			}
		}
	}
}
