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
