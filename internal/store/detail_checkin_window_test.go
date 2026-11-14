package store

import (
	"reflect"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/model"
)

func detailWindowCases(t0 time.Time) []struct {
	name string
	now  time.Time
	want []int64
} {
	edge := t0.Add(DetailCheckinWindow)
	return []struct {
		name string
		now  time.Time
		want []int64
	}{
		{"one second before the edge", edge.Add(-time.Second), []int64{1, 2, 3}},
		{"one nanosecond before the edge", edge.Add(-time.Nanosecond), []int64{2, 3}},
		{"on the edge", edge, []int64{2, 3}},
		{"one nanosecond after", edge.Add(time.Nanosecond), []int64{3}},
		{"half a second after", edge.Add(500 * time.Millisecond), []int64{3}},
		{"just under a second after", edge.Add(999 * time.Millisecond), []int64{3}},
		{"one second after", edge.Add(time.Second), []int64{3}},
	}
}

func TestDetailCheckinWindowStartsOnAStoredSecond(t *testing.T) {
	s := newTestStore(t)
	t0 := time.Date(2026, 9, 9, 19, 0, 0, 0, time.UTC)
	id := mustEnroll(t, s, "window-edge", t0.Add(-time.Hour))
	for i := 0; i < 3; i++ {
		at := t0.Add(time.Duration(i-1) * time.Second)
		if err := s.RecordCheckin(id, model.Checkin{
			SchemaVersion: model.SchemaVersion, SentAt: at, AgentVersion: "v3",
			BootID: "boot-one", AgentSeq: int64(i + 1), AgentStartedAt: t0.Add(-time.Hour),
			DiskFreeBytes: 50, DiskTotalBytes: 100,
		}, at); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range detailWindowCases(t0) {
		t.Run(tc.name, func(t *testing.T) {
			detail, err := s.Detail(id, tc.now)
			if err != nil {
				t.Fatal(err)
			}
			var got []int64
			for _, p := range detail.Checkins {
				got = append(got, p.AgentSeq)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("sequences = %v, want %v", got, tc.want)
			}
			for _, p := range detail.Checkins {
				if p.ReceivedAt.Before(tc.now.Add(-DetailCheckinWindow)) {
					t.Fatalf("check-in %d received at %s before window start %s", p.AgentSeq, p.ReceivedAt, tc.now.Add(-DetailCheckinWindow))
				}
			}
		})
	}
}

func TestDetailCheckinWindowStart(t *testing.T) {
	t0 := time.Date(2026, 9, 9, 19, 0, 0, 0, time.UTC)
	for _, tc := range detailWindowCases(t0) {
		t.Run(tc.name, func(t *testing.T) {
			got := detailCheckinWindowStart(tc.now)
			start := tc.now.Add(-DetailCheckinWindow)
			if got.Nanosecond() != 0 || got.Before(start) || got.Sub(start) >= time.Second {
				t.Fatalf("window start = %s, want a whole second at or after %s and less than one second later", got, start)
			}
		})
	}
}
