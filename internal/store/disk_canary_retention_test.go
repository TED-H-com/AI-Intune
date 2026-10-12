package store

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestDiskCanaryRetentionBoundAndGateWindow(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	machine := req.Targets[0]
	raw, _ := json.Marshal(DefaultDiskPolicy())
	_, _, digest, err := CanonicalDiskPolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	insert := func(machine, day string) {
		t.Helper()
		if _, err := s.db.Exec(`INSERT INTO disk_canary_days(machine_id,scope,day,local_summary_at,hub_summary_at,agreement,policy_digest,local_candidate_bytes,hub_candidate_bytes) VALUES(?,'user',?,'','',1,?,0,0)`, machine, day, digest); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 1005; i++ {
		insert(fmt.Sprintf("expired-%d", i), now.AddDate(0, 0, -90).Format("2006-01-02"))
	}
	for i := 0; i < 7; i++ {
		insert(machine, now.AddDate(0, 0, -i).Format("2006-01-02"))
	}
	insert(machine, now.AddDate(0, 0, -89).Format("2006-01-02"))
	insert(machine, now.AddDate(0, 0, 1).Format("2006-01-02"))
	before, err := s.DiskCanaryGet(machine, "user", now)
	if err != nil || !before.Satisfied || len(before.Days) != 7 {
		t.Fatalf("gate before retention: %+v %v", before, err)
	}
	if err = s.PruneDiskCanaryDays(now); err != nil {
		t.Fatal(err)
	}
	var expired int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM disk_canary_days WHERE machine_id LIKE 'expired-%'`).Scan(&expired); err != nil || expired != 5 {
		t.Fatalf("batch remaining=%d %v", expired, err)
	}
	if err = s.PruneDiskCanaryDays(now); err != nil {
		t.Fatal(err)
	}
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM disk_canary_days WHERE machine_id LIKE 'expired-%'`).Scan(&expired); err != nil || expired != 0 {
		t.Fatalf("expired remaining=%d %v", expired, err)
	}
	after, err := s.DiskCanaryGet(machine, "user", now)
	if err != nil || !after.Satisfied || after.AgreedDays != before.AgreedDays || len(after.Days) != 7 {
		t.Fatalf("gate after retention: %+v %v", after, err)
	}
	var kept int
	if err = s.db.QueryRow(`SELECT COUNT(*) FROM disk_canary_days WHERE machine_id=? AND day=?`, machine, now.AddDate(0, 0, -89).Format("2006-01-02")).Scan(&kept); err != nil || kept != 1 {
		t.Fatal("maximum policy window lost", kept, err)
	}
}
