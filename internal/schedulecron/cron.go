// Package schedulecron implements numeric five-field cron in UTC.
package schedulecron

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Cron struct {
	fields           [5]map[int]bool
	domStar, dowStar bool
	minutes          []int
}

func Parse(expr string) (*Cron, error) {
	parts := strings.Fields(expr)
	if len(parts) != 5 {
		return nil, fmt.Errorf("cron requires five numeric fields")
	}
	c := &Cron{domStar: strings.HasPrefix(parts[2], "*"), dowStar: strings.HasPrefix(parts[4], "*")}
	lo := []int{0, 0, 1, 1, 0}
	hi := []int{59, 23, 31, 12, 7}
	for i, p := range parts {
		c.fields[i] = map[int]bool{}
		for _, item := range strings.Split(p, ",") {
			seg := strings.Split(item, "/")
			if len(seg) > 2 {
				return nil, fmt.Errorf("invalid cron step")
			}
			step := 1
			if len(seg) == 2 {
				v, e := strconv.Atoi(seg[1])
				if e != nil || v < 1 || v > hi[i]+1 {
					return nil, fmt.Errorf("invalid cron step")
				}
				step = v
			}
			start, end := lo[i], hi[i]
			if seg[0] != "*" {
				r := strings.Split(seg[0], "-")
				if len(r) > 2 {
					return nil, fmt.Errorf("invalid cron range")
				}
				v, e := strconv.Atoi(r[0])
				if e != nil {
					return nil, e
				}
				start = v
				end = v
				if len(r) == 2 {
					end, e = strconv.Atoi(r[1])
					if e != nil {
						return nil, e
					}
				} else if len(seg) == 2 {
					end = hi[i]
				}
			}
			if start < lo[i] || end > hi[i] || start > end {
				return nil, fmt.Errorf("cron range out of bounds")
			}
			for v := start; v <= end; v += step {
				if i == 4 && v == 7 {
					c.fields[i][0] = true
				} else {
					c.fields[i][v] = true
				}
			}
		}
	}
	for h := 0; h < 24; h++ {
		for m := 0; m < 60; m++ {
			if c.fields[1][h] && c.fields[0][m] {
				c.minutes = append(c.minutes, h*60+m)
			}
		}
	}
	// The Gregorian calendar repeats every 400 years. Check both within-day
	// gaps and adjacent matching dates, including the cycle boundary.
	for i := 1; i < len(c.minutes); i++ {
		if c.minutes[i]-c.minutes[i-1] < 5 {
			return nil, fmt.Errorf("cron interval must be at least five minutes")
		}
	}
	var last time.Time
	found := false
	for d := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC); d.Before(time.Date(2401, 1, 1, 0, 0, 0, 0, time.UTC)); d = d.AddDate(0, 0, 1) {
		if !c.day(d) {
			continue
		}
		first := d.Add(time.Duration(c.minutes[0]) * time.Minute)
		if !last.IsZero() && first.Sub(last) < 5*time.Minute {
			return nil, fmt.Errorf("cron interval must be at least five minutes")
		}
		last = d.Add(time.Duration(c.minutes[len(c.minutes)-1]) * time.Minute)
		found = true
	}
	if !found {
		return nil, fmt.Errorf("cron never runs")
	}
	return c, nil
}
func (c *Cron) day(t time.Time) bool {
	if !c.fields[3][int(t.Month())] {
		return false
	}
	dom, dow := c.fields[2][t.Day()], c.fields[4][int(t.Weekday())]
	if c.domStar || c.dowStar {
		return dom && dow
	}
	return dom || dow
}
func (c *Cron) Next(after time.Time) time.Time {
	after = after.UTC()
	d := time.Date(after.Year(), after.Month(), after.Day(), 0, 0, 0, 0, time.UTC)
	for limit := d.AddDate(8, 0, 0); d.Before(limit); d = d.AddDate(0, 0, 1) {
		if c.day(d) {
			for _, m := range c.minutes {
				t := d.Add(time.Duration(m) * time.Minute)
				if t.After(after) {
					return t
				}
			}
		}
	}
	return time.Time{}
}
