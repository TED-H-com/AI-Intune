package operator

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
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
	got, err := svc.ListStaleMachineCandidates(now, "", all)
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
	scoped, err := svc.ListStaleMachineCandidates(now, "", scope)
	if err != nil || len(scoped.Items) != 1 || scoped.Items[0].MachineID != "candidate" || !reflect.DeepEqual(scoped.Items[0].DuplicateOf, []string{"reporting"}) {
		t.Fatalf("scope %+v %v", scoped, err)
	}
	hidden, err := svc.ListStaleMachineCandidates(now, "", func(string) bool { return false })
	if err != nil || len(hidden.Items) != 0 || hidden.Truncated {
		t.Fatalf("hidden %+v %v", hidden, err)
	}
	if _, err := svc.ListStaleMachineCandidates(now, "", nil); err == nil {
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
	after, err := svc.ListStaleMachineCandidates(time.Now().UTC(), "", scope)
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
	empty, err := svc.ListStaleMachineCandidates(now, "", all)
	if err != nil || empty.Items == nil || len(empty.Items) != 0 || empty.Truncated {
		t.Fatalf("empty %+v %v", empty, err)
	}
	for i := 0; i < 102; i++ {
		id := fmt.Sprintf("m-%03d", i)
		if _, err := st.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,?,?)`, id, id, now.Add(-25*time.Hour).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	got, err := svc.ListStaleMachineCandidates(now, "", all)
	if err != nil || len(got.Items) != 100 || !got.Truncated || got.Items[0].MachineID != "m-000" || got.Items[99].MachineID != "m-099" {
		t.Fatalf("bound %+v %v", got, err)
	}
	scoped, err := svc.ListStaleMachineCandidates(now, "", func(id string) bool { return id == "m-101" })
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
	got, err := svc.ListStaleMachineCandidates(now, "", func(string) bool { return true })
	if err != nil || len(got.Items) != 1 || len(got.Items[0].DuplicateOf) != 100 || !got.Items[0].RelatedTruncated {
		t.Fatalf("related bound %+v %v", got, err)
	}
	got, err = svc.ListStaleMachineCandidates(now, "", func(id string) bool { return id == "candidate" || id == "reporting-101" })
	if err != nil || len(got.Items) != 1 || !reflect.DeepEqual(got.Items[0].DuplicateOf, []string{"reporting-101"}) || got.Items[0].RelatedTruncated {
		t.Fatalf("related scope %+v %v", got, err)
	}
	var audits int
	if err := st.DB().QueryRow(`SELECT count(*) FROM audit_log`).Scan(&audits); err != nil || audits != 0 {
		t.Fatalf("read wrote audit: %d %v", audits, err)
	}
}

func TestStaleMachineReviewKeysetTraversalAndRetiredAnchor(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "hub.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc := New(st)
	now := time.Now().UTC()
	all := func(string) bool { return true }
	// Multiple creation times plus tied IDs exercise both parts of the ascending key.
	for i := 0; i < 205; i++ {
		id := fmt.Sprintf("page-%03d", i)
		if _, err := st.DB().Exec(`INSERT INTO machine_registry(machine_id,display_name,created_at) VALUES(?,?,?)`, id, id, now.Add(-48*time.Hour+time.Duration(i/3)*time.Second).Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	first, err := svc.ListStaleMachineCandidates(now, "", all)
	if err != nil || len(first.Items) != 100 || first.NextCursor == nil {
		t.Fatalf("first page: %+v %v", first, err)
	}
	checkRest := func(cursor string) {
		t.Helper()
		count := 100
		for cursor != "" {
			page, err := svc.ListStaleMachineCandidates(now, cursor, all)
			if err != nil {
				t.Fatal(err)
			}
			for _, item := range page.Items {
				if item.MachineID != fmt.Sprintf("page-%03d", count) {
					t.Fatalf("duplicate/skip at %d: %s", count, item.MachineID)
				}
				count++
			}
			cursor = ""
			if page.NextCursor != nil {
				cursor = *page.NextCursor
			}
		}
		if count != 205 {
			t.Fatalf("visited %d of 205", count)
		}
	}
	checkRest(*first.NextCursor) // The entire list is inspectable with no mutation.
	var writes int
	if err := st.DB().QueryRow(`SELECT count(*) FROM machine_registry_lifecycle_events`).Scan(&writes); err != nil || writes != 0 {
		t.Fatalf("read wrote lifecycle: %d %v", writes, err)
	}
	anchor := first.Items[99]
	revision := int64(0)
	preview, err := svc.PreviewMachineLifecycle(MachineLifecyclePreviewRequest{MachineID: anchor.MachineID, DesiredState: MachineLifecycleStateRetired, ExpectedRevision: &revision})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ChangeMachineLifecycle(MachineLifecycleRequest{MachineID: anchor.MachineID, DesiredState: MachineLifecycleStateRetired, ExpectedRevision: &revision, ConfirmDisplayName: anchor.DisplayName, PreviewDigest: preview.PreviewDigest, Reason: "reviewed", IdempotencyKey: "retire-page-anchor"}); err != nil {
		t.Fatal(err)
	}
	checkRest(*first.NextCursor) // No lookup of the now-retired anchor, no offset skips.
	scoped, err := svc.ListStaleMachineCandidates(now, "", func(id string) bool { return id <= "page-100" })
	if err != nil || len(scoped.Items) != 100 || scoped.Truncated || scoped.NextCursor != nil {
		t.Fatalf("hidden lookahead leaked: %+v %v", scoped, err)
	}
	denied, err := svc.ListStaleMachineCandidates(now, *first.NextCursor, func(string) bool { return false })
	if err != nil || len(denied.Items) != 0 || denied.NextCursor != nil {
		t.Fatalf("continuation scope: %+v %v", denied, err)
	}
}

func TestStaleMachineCursorStrictValidation(t *testing.T) {
	maxID := strings.Repeat("<", 256)
	position := MachineReadPosition{CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 123, time.UTC), MachineID: maxID}
	encoded, err := EncodeStaleMachineCursor(position)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeStaleMachineCursor(encoded)
	if err != nil || decoded != position {
		t.Fatalf("bounded ID/fractional timestamp roundtrip: %+v %v", decoded, err)
	}

	good, err := EncodeStaleMachineCursor(MachineReadPosition{CreatedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), MachineID: "m-1"})
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(good)
	invalid := []string{"", "bad", good + "=", good + "\n", strings.Repeat("a", MaxStaleMachineCursorBytes+1)}
	for _, doc := range []string{
		`null`, `{}`, string(raw) + `{}`, strings.Replace(string(raw), `"v":1`, `"v":2`, 1),
		strings.Replace(string(raw), `"v":1`, `"v":1,"v":1`, 1), strings.Replace(string(raw), `"v":1`, `"V":1`, 1),
		strings.Replace(string(raw), `"v":1`, `"v":1,"extra":true`, 1), strings.Replace(string(raw), `"m-1"`, `null`, 1),
		strings.Replace(string(raw), `"m-1"`, `""`, 1), strings.Replace(string(raw), `"m-1"`, `" m-1"`, 1),
		strings.Replace(string(raw), `"m-1"`, `"m\u0000"`, 1), strings.Replace(string(raw), `2026-01-01T00:00:00Z`, `0001-01-01T00:00:00Z`, 1),
		strings.Replace(string(raw), `2026-01-01T00:00:00Z`, `2026-01-01T01:00:00+01:00`, 1),
	} {
		invalid = append(invalid, base64.RawURLEncoding.EncodeToString([]byte(doc)))
	}
	for _, cursor := range invalid {
		if _, err := DecodeStaleMachineCursor(cursor); err == nil {
			t.Fatalf("accepted invalid cursor %q", cursor)
		}
	}
	if got, err := ParseStaleMachineReviewQuery("cursor="+good, false); err != nil || got != good {
		t.Fatalf("valid query: %s %v", got, err)
	}
	for _, query := range []string{"cursor=", "cursor=bad", "limit=1", "cursor=" + good + "&cursor=" + good, "cursor=" + good + "&x=1", "cursor=%zz", "cursor=" + strings.Repeat("a", 7000), "cursor=" + good + ";x=1"} {
		if _, err := ParseStaleMachineReviewQuery(query, false); err == nil {
			t.Fatalf("accepted query %q", query)
		}
	}
	if _, err := ParseStaleMachineReviewQuery("", true); err == nil {
		t.Fatal("accepted empty query marker")
	}
}
