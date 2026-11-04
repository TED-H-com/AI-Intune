package operator

import (
	"fmt"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/teddashh/AI-Intune/internal/store"
)

func TestStaleMachineReviewEvidenceScopeAndRetirement(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.DB().Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"candidate", "hidden-candidate", "reporting", "hidden-reporting", "enrolled", "live-ticket", "expired-ticket", "live-join", "expired-join", "young"} {
		name := id
		age := 25 * time.Hour
		if id == "candidate" || id == "reporting" || id == "hidden-reporting" {
			name = "same"
			age = 2 * time.Hour
		}
		if id == "young" {
			age = 30 * time.Minute
		}
		exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,?,?)`, id, name, now.Add(-age).Format(time.RFC3339))
	}
	for _, id := range []string{"reporting", "hidden-reporting"} {
		exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at) VALUES(?,?,?)`, id, now.Format(time.RFC3339), now.Format(time.RFC3339))
	}
	exec(`UPDATE machine_registry SET enrolled_at=? WHERE machine_id='enrolled'`, now.Format(time.RFC3339))
	for _, kind := range []string{"ticket", "join"} {
		for _, state := range []string{"live", "expired"} {
			id := state + "-" + kind
			expires := now.Add(time.Hour)
			if state == "expired" {
				expires = now.Add(-time.Hour)
			}
			if kind == "ticket" {
				exec(`INSERT INTO enrollment_tokens(token_hash,display_name,created_at,expires_at) VALUES(?,?,?,?)`, id, id, now.Format(time.RFC3339), expires.Format(time.RFC3339))
			} else {
				exec(`INSERT INTO join_requests(code,secret_hash,hostname,os,arch,user,client_ip,created_at,expires_at,state) VALUES(?,?,?,'','','','',?,?,'pending')`, id, id, id, now.Format(time.RFC3339), expires.Format(time.RFC3339))
			}
		}
	}
	svc := New(st)
	all := func(string) bool { return true }
	got, err := svc.ListStaleMachineCandidates(now, all)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := st.StaleMachineCandidates(now)
	if err != nil || len(got.Items) != len(raw) {
		t.Fatalf("store parity %v %+v", err, got)
	}
	for i, c := range raw {
		if got.Items[i].MachineID != c.MachineID || !reflect.DeepEqual(got.Items[i].Branches, c.Branches) || !reflect.DeepEqual(got.Items[i].DuplicateOf, c.DuplicateOf) {
			t.Fatalf("changed evidence %+v %+v", got.Items[i], c)
		}
	}
	scope := func(id string) bool { return id == "candidate" || id == "reporting" }
	scoped, err := svc.ListStaleMachineCandidates(now, scope)
	if err != nil || len(scoped.Items) != 1 || scoped.Items[0].MachineID != "candidate" || !reflect.DeepEqual(scoped.Items[0].DuplicateOf, []string{"reporting"}) {
		t.Fatalf("scope %+v %v", scoped, err)
	}
	hidden, err := svc.ListStaleMachineCandidates(now, func(string) bool { return false })
	if err != nil || len(hidden.Items) != 0 || hidden.Truncated {
		t.Fatalf("hidden %+v %v", hidden, err)
	}
	if _, err := svc.ListStaleMachineCandidates(now, nil); err == nil {
		t.Fatal("nil scope accepted")
	}
	ids := map[string]bool{}
	for _, c := range got.Items {
		ids[c.MachineID] = true
	}
	if len(ids) != 4 || !ids["candidate"] || !ids["hidden-candidate"] || !ids["expired-ticket"] || !ids["expired-join"] {
		t.Fatalf("eligibility %v", ids)
	}
	revision := int64(0)
	preview, err := svc.PreviewMachineLifecycle(MachineLifecyclePreviewRequest{MachineID: "candidate", DesiredState: MachineLifecycleStateRetired, ExpectedRevision: &revision})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.ChangeMachineLifecycle(MachineLifecycleRequest{MachineID: "candidate", DesiredState: MachineLifecycleStateRetired, ExpectedRevision: &revision, ConfirmDisplayName: "same", PreviewDigest: preview.PreviewDigest, Reason: "reviewed unused registration", IdempotencyKey: "review-retire"})
	if err != nil {
		t.Fatal(err)
	}
	after, err := svc.ListStaleMachineCandidates(time.Now().UTC(), scope)
	if err != nil || len(after.Items) != 0 {
		t.Fatalf("retired candidate %+v %v", after, err)
	}
}

func TestStaleMachineReviewEmptyAndBounds(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc := New(st)
	now := time.Now().UTC()
	all := func(string) bool { return true }
	empty, err := svc.ListStaleMachineCandidates(now, all)
	if err != nil || empty.Items == nil || len(empty.Items) != 0 || empty.Truncated {
		t.Fatalf("empty %+v %v", empty, err)
	}
	for i := 0; i < 102; i++ {
		id := fmt.Sprintf("m-%03d", i)
		if _, err := st.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,?,?)`, id, id, now.Add(-25*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := svc.ListStaleMachineCandidates(now, all)
	if err != nil || len(got.Items) != 100 || !got.Truncated || got.Items[0].MachineID != "m-000" || got.Items[99].MachineID != "m-099" {
		t.Fatalf("bound %+v %v", got, err)
	}
	scoped, err := svc.ListStaleMachineCandidates(now, func(id string) bool { return id == "m-101" })
	if err != nil || len(scoped.Items) != 1 || scoped.Truncated {
		t.Fatalf("scoped bound %+v %v", scoped, err)
	}
}

func TestStaleMachineReviewRelatedBoundsAfterScope(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	stamp := now.Format(time.RFC3339)
	if _, err := st.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES('candidate','shared',?)`, now.Add(-2*time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 102; i++ {
		id := fmt.Sprintf("reporting-%03d", i)
		if _, err := st.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,'shared',?)`, id, stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := st.DB().Exec(`INSERT INTO machine_checkins(machine_id,sent_at,received_at) VALUES(?,?,?)`, id, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	svc := New(st)
	got, err := svc.ListStaleMachineCandidates(now, func(string) bool { return true })
	if err != nil || len(got.Items) != 1 || len(got.Items[0].DuplicateOf) != 100 || !got.Items[0].RelatedTruncated {
		t.Fatalf("related bound %+v %v", got, err)
	}
	got, err = svc.ListStaleMachineCandidates(now, func(id string) bool { return id == "candidate" || id == "reporting-101" })
	if err != nil || len(got.Items) != 1 || !reflect.DeepEqual(got.Items[0].DuplicateOf, []string{"reporting-101"}) || got.Items[0].RelatedTruncated {
		t.Fatalf("related scope %+v %v", got, err)
	}
	var audits int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_log`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("read wrote audit: %d %v", audits, err)
	}
}
