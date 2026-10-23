package store

import (
	"fmt"
	"strings"
	"testing"
)

func TestDiskAlertBannerNarrowIndexedCounts(t *testing.T) {
	s, req, now := safeDiskFixture(t)
	for i := 0; i < 4; i++ {
		severity := "warn"
		if i%2 == 0 {
			severity = "critical"
		}
		var cleared any
		if i >= 2 {
			cleared = fmtTime(now)
		}
		if _, err := s.db.Exec(`INSERT INTO disk_alerts(id,machine_id,condition_key,severity,opened_at,cleared_at,last_reading) VALUES(?,?,?,?,?,?,?)`, fmt.Sprintf("banner-%d", i), req.Targets[0], fmt.Sprintf("banner-%d", i), severity, fmtTime(now), cleared, fmtTime(now)); err != nil {
			t.Fatal(err)
		}
	}
	counts, err := s.DiskAlertBannerCounts()
	if err != nil || counts.OpenCritical != 1 || counts.OpenWarn != 1 {
		t.Fatalf("counts=%+v err=%v", counts, err)
	}
	rows, err := s.rdb.Query(`EXPLAIN QUERY PLAN ` + diskAlertBannerQuery)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	indexed := false
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err = rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		indexed = indexed || strings.Contains(detail, "disk_alert_banner_open")
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !indexed {
		t.Fatal("banner counts did not use the partial open-alert index")
	}
}
