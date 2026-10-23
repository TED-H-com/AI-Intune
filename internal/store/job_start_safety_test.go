package store

import (
	"database/sql"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/deploy"
)

func TestJobStartRejectsDesiredStateLookupFailures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt func(*testing.T, *Store, string)
		want    string
		missing bool
	}{
		{name: "missing desired state row", missing: true, want: "read job desired state", corrupt: func(t *testing.T, s *Store, desiredID string) {
			// Simulate an orphaned reference without changing the claimed job or lease.
			if _, err := s.db.Exec(`PRAGMA foreign_keys=OFF`); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`DELETE FROM desired_state WHERE desired_id=?`, desiredID); err != nil {
				t.Fatal(err)
			}
			if _, err := s.db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "lookup error", want: "read job desired state", corrupt: func(t *testing.T, s *Store, _ string) {
			if _, err := s.db.Exec(`ALTER TABLE desired_state RENAME TO unavailable_desired_state`); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "unknown catalog entry", want: "unknown script id", corrupt: func(t *testing.T, s *Store, desiredID string) {
			if _, err := s.db.Exec(`UPDATE desired_state SET spec='{"kind":"script_v1","script_id":"unknown-script"}' WHERE desired_id=?`, desiredID); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, req, now := safeDiskFixture(t)
			preview, err := s.ScriptRun(req, false, "", diskAdmin())
			if err != nil {
				t.Fatal(err)
			}
			req.PreviewDigest = preview.PreviewDigest
			run, err := s.ScriptRun(req, true, "start-lookup", diskAdmin())
			if err != nil {
				t.Fatal(err)
			}
			jobID := run.JobIDs[0]
			token, err := s.ClaimJob(jobID, req.Targets[0], now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			before, err := s.Job(jobID)
			if err != nil {
				t.Fatal(err)
			}
			tc.corrupt(t, s, before.DesiredID)
			state, err := s.AdvanceJobByAgent(jobID, req.Targets[0], token, deploy.Start, now)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Start returned %q, %v", state, err)
			}
			if tc.missing && !errors.Is(err, sql.ErrNoRows) {
				t.Fatalf("missing row error not preserved: %v", err)
			}
			if state != deploy.Claimed {
				t.Fatalf("returned state = %q", state)
			}
			after, err := s.Job(jobID)
			if err != nil {
				t.Fatal(err)
			}
			if after.State != before.State || after.LeaseToken != before.LeaseToken || after.TerminalAt != before.TerminalAt {
				t.Fatalf("rejected Start changed job: before=%+v after=%+v", before, after)
			}
		})
	}
}
