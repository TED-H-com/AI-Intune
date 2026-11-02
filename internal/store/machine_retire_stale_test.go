package store

import (
	"testing"
	"time"
)

func TestStaleMachineCandidates(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, test := range []struct {
		name                            string
		age                             time.Duration
		dup, checkin, enrolled, retired bool
		pending                         string
		want                            bool
	}{
		{name: "duplicate", age: 2 * time.Hour, dup: true, want: true},
		{name: "abandoned", age: 25 * time.Hour, want: true},
		{name: "young duplicate", age: 30 * time.Minute, dup: true},
		{name: "young unique", age: 23 * time.Hour},
		{name: "ever checked in", age: 25 * time.Hour, checkin: true},
		{name: "retired", age: 25 * time.Hour, retired: true},
		{name: "active", age: 25 * time.Hour, checkin: true, enrolled: true},
		{name: "pending token", age: 25 * time.Hour, pending: "token"},
		{name: "pending join", age: 25 * time.Hour, pending: "join"},
		{name: "expired token", age: 25 * time.Hour, pending: "expired", want: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			st := newTestStore(t)
			exec := func(q string, args ...any) {
				t.Helper()
				if _, err := st.db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			var retiredAt any
			if test.retired {
				retiredAt = fmtTime(now)
			}
			exec(`INSERT INTO machine_registry(machine_id,display_name,hostname,created_at,retired_at) VALUES('candidate','name','host',?,?)`, fmtTime(now.Add(-test.age)), retiredAt)
			if test.dup {
				exec(`INSERT INTO machine_registry(machine_id,display_name,hostname,created_at,enrolled_at) VALUES('active','host','other',?,?)`, fmtTime(now.Add(-48*time.Hour)), fmtTime(now))
				exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at) VALUES('active',?,?)`, fmtTime(now), fmtTime(now))
			}
			if test.checkin {
				exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at) VALUES('candidate',?,?)`, fmtTime(now), fmtTime(now))
			}
			if test.enrolled {
				exec(`UPDATE machine_registry SET enrolled_at=? WHERE machine_id='candidate'`, fmtTime(now))
			}
			if test.pending == "token" || test.pending == "expired" {
				expiry := now.Add(time.Hour)
				if test.pending == "expired" {
					expiry = now.Add(-time.Second)
				}
				exec(`INSERT INTO enrollment_tokens(token_hash,display_name,created_at,expires_at) VALUES('token','host',?,?)`, fmtTime(now), fmtTime(expiry))
			}
			if test.pending == "join" {
				exec(`INSERT INTO join_requests(code,secret_hash,hostname,os,arch,user,client_ip,created_at,expires_at,state) VALUES('code','hash','name','','','','',?,?,'pending')`, fmtTime(now), fmtTime(now.Add(time.Hour)))
			}
			got, err := st.StaleMachineCandidates(now)
			if err != nil {
				t.Fatal(err)
			}
			if (len(got) == 1) != test.want {
				t.Fatalf("candidates=%+v want=%v", got, test.want)
			}
			c, ok, err := st.StaleMachineCandidate("candidate", now)
			if err != nil || ok != test.want {
				t.Fatalf("recheck=%+v %v %v", c, ok, err)
			}
			if test.want {
				branch := StaleMachineAbandoned24h
				if test.dup {
					branch = StaleMachineDuplicateOfActive
				}
				if len(c.Branches) != 1 || c.Branches[0] != branch {
					t.Fatalf("branches=%v", c.Branches)
				}
				if test.dup && (len(c.DuplicateOf) != 1 || c.DuplicateOf[0] != "active") {
					t.Fatalf("duplicates=%v", c.DuplicateOf)
				}
			}
		})
	}
}

func TestStaleMachineMatchingAndTimeBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, names := range [][4]string{{"same", "c-host", "same", "a-host"}, {"same", "c-host", "a-name", "same"}, {"c-name", "same", "same", "a-host"}, {"c-name", "same", "a-name", "same"}, {"", "", "", ""}} {
		t.Run(names[0]+names[1]+names[2]+names[3], func(t *testing.T) {
			st := newTestStore(t)
			for i, id := range []string{"candidate", "active"} {
				created := now.Add(-time.Hour).In(time.FixedZone("offset", -5*3600)).Format(time.RFC3339Nano)
				if _, err := st.db.Exec(`INSERT INTO machine_registry(machine_id,display_name,hostname,created_at) VALUES(?,?,?,?)`, id, names[i*2], names[i*2+1], created); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := st.db.Exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at) VALUES('active',?,?)`, fmtTime(now), fmtTime(now)); err != nil {
				t.Fatal(err)
			}
			got, err := st.StaleMachineCandidates(now)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if names[0] == "" {
				want = 0
			}
			if len(got) != want {
				t.Fatalf("candidates=%+v", got)
			}
			if _, err := st.db.Exec(`UPDATE machine_registry SET created_at=? WHERE machine_id='candidate'`, now.Add(-24*time.Hour).Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
			got, err = st.StaleMachineCandidates(now)
			if err != nil || len(got) != 1 {
				t.Fatalf("24h candidates=%+v err=%v", got, err)
			}
			wantBranches := 2
			if names[0] == "" {
				wantBranches = 1
			}
			if len(got[0].Branches) != wantBranches {
				t.Fatalf("branches=%v", got[0].Branches)
			}
		})
	}
}
