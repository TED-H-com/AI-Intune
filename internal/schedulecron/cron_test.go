package schedulecron

import (
	"testing"
	"time"
)

func TestCron(t *testing.T) {
	for _, expr := range []string{"* * * * *", "*/4 * * * *", "0,3 * * * *", "58,1 * * * *", "0 0 31 2 *", "0 0 * * * *", "60 * * * *"} {
		if _, e := Parse(expr); e == nil {
			t.Errorf("accepted %s", expr)
		}
	}
	for _, expr := range []string{"*/5 * * * *", "17 * * * *", "23 7 * * *", "0 0 29 2 *", "0 0 * * 7"} {
		if _, e := Parse(expr); e != nil {
			t.Errorf("%s: %v", expr, e)
		}
	}
	c, e := Parse("0 7 * * *")
	if e != nil {
		t.Fatal(e)
	}
	loc, e := time.LoadLocation("America/New_York")
	if e != nil {
		t.Fatal(e)
	}
	for _, date := range []string{"2026-03-08T06:59:59Z", "2026-11-01T06:59:59Z"} {
		now, _ := time.Parse(time.RFC3339, date)
		got := c.Next(now.In(loc))
		if got.Location() != time.UTC || got.Sub(now) != time.Second {
			t.Fatal(got)
		}
	}
	c, _ = Parse("0 0 29 2 *")
	after := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	if c.Next(after).Year() != 2028 {
		t.Fatal("leap next")
	}
}

func TestCronTimezoneDST(t *testing.T) {
	loc, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ cron, after, want string }{
		{"30 1 * * *", "2026-11-01T04:00:00Z", "2026-11-01T05:30:00Z"},
		{"30 1 * * *", "2026-11-01T05:30:00Z", "2026-11-02T06:30:00Z"},
		{"30 2 * * *", "2027-03-14T05:00:00Z", "2027-03-15T06:30:00Z"},
		{"0 12 * * *", "2026-11-01T04:00:00Z", "2026-11-01T17:00:00Z"},
		{"0 12 * * *", "2027-03-14T05:00:00Z", "2027-03-14T16:00:00Z"},
	} {
		c, err := Parse(test.cron)
		if err != nil {
			t.Fatal(err)
		}
		after, _ := time.Parse(time.RFC3339, test.after)
		if got := c.NextIn(after, loc).Format(time.RFC3339); got != test.want {
			t.Errorf("%s after %s: %s want %s", test.cron, test.after, got, test.want)
		}
	}
}
