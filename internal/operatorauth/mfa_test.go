package operatorauth

import (
	"testing"
	"time"
)

func TestMFAWithin(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		at   time.Time
		want bool
	}{{now, true}, {now.Add(-time.Hour), true}, {now.Add(-DefaultAdminMFAWindow), false}, {time.Time{}, false}, {now.Add(time.Second), false}} {
		if got := MFAWithin(tc.at, now, DefaultAdminMFAWindow); got != tc.want {
			t.Fatalf("timestamp %v: %v", tc.at, got)
		}
	}
}
