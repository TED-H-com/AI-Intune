package store

import (
	"errors"
	"testing"
	"time"
)

func TestUsageUploadToolCallLimit(t *testing.T) {
	for _, limit := range []int{DefaultUsageToolCallLimit, 2} {
		s, machine, in := usageFixture(t)
		if limit != DefaultUsageToolCallLimit {
			if err := s.ConfigureUsageToolCallLimit(limit); err != nil {
				t.Fatal(err)
			}
		}
		for _, invalid := range []int{0, -1} {
			if err := s.ConfigureUsageToolCallLimit(invalid); !errors.Is(err, ErrUsageInvalid) {
				t.Fatalf("invalid configuration: %v", err)
			}
		}
		base := in.Daily[0]
		base.Metrics.ToolCalls = map[string]int64{"Read": 1}
		in.Daily = nil
		day, _ := time.Parse("2006-01-02", base.Period)
		for i := 0; i < limit; i++ {
			a := base
			a.Period = day.AddDate(0, 0, -i).Format("2006-01-02")
			in.Daily = append(in.Daily, a)
		}
		// Daily and window entries share one cap, checked before any writes.
		window := base
		window.Period = day.Format(time.RFC3339)
		in.Window = []UsageAggregate{window}
		if changed, err := s.MergeUsageFile(machine, in); changed || !errors.Is(err, ErrUsageUploadTooLarge) {
			t.Fatalf("limit %d over-cap: %t, %v", limit, changed, err)
		}
		for _, table := range []string{"usage_daily", "usage_window", "usage_upload_receipts"} {
			if n := countRows(t, s, "SELECT count(*) FROM "+table); n != 0 {
				t.Fatalf("over-cap wrote %s", table)
			}
		}
		in.Window = nil
		if changed, err := s.MergeUsageFile(machine, in); !changed || err != nil {
			t.Fatalf("limit %d boundary: %t, %v", limit, changed, err)
		}
	}
}
