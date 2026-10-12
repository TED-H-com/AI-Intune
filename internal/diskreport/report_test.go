package diskreport

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPublicProjectionNeverExposesPrivateFields(t *testing.T) {
	item := Item{ID: "candidate", PrivatePath: "/home/private-user/private-project/archive.tar.gz", Category: "duplicate-archives", OwnerApp: "/home/private-user", LastUsedSource: "/secret/config", Confidence: "high", SuggestedAction: "quarantine", EvidenceStrength: "weak", ExclusionReason: "private facts", ContentDigest: "private digest", BootID: "private boot", Identity: Identity{Inode: 42}}
	p := PublicItem(item)
	raw, _ := json.Marshal(p)
	for _, bad := range []string{"private-user", "private-project", "private facts", "private digest", "private boot", "private_path", "/secret/"} {
		if strings.Contains(string(raw), bad) {
			t.Fatal("leaked", bad)
		}
	}
	if p.DisplayPath != "~/…/archive.tar.gz" || PublicItem(p).DisplayPath != p.DisplayPath {
		t.Fatal("display projection is not idempotent")
	}
	meta := PublicReport(Report{Notices: []string{"/home/private-user"}, InaccessibleRoots: []string{"/home/private-user"}, Excluded: map[string]Aggregate{"/home/private-user": {Count: 1, AllocatedBytes: 4096}}})
	raw, _ = json.Marshal(meta)
	if strings.Contains(string(raw), "private-user") {
		t.Fatal("metadata leaked")
	}
}

func TestDisplayedPathsScrubUnicodeAndControls(t *testing.T) {
	for _, unsafe := range []string{"\u202e", "\u2066", "\u200b", "\u200d", "\u00ad", "\x1b", "\t", "\x7f"} {
		path := "/home/example/arch" + unsafe + "ive.bak"
		i := StoredItem(Item{PrivatePath: path, OwnerApp: "app" + unsafe, ExclusionReason: "reason" + unsafe})
		if i.PrivatePath != path {
			t.Fatal("private identity binding changed")
		}
		for _, value := range []string{i.DisplayPath, i.OwnerApp, i.ExclusionReason, ScrubDisplay(path)} {
			if strings.Contains(value, unsafe) {
				t.Fatalf("unsafe display %q", value)
			}
		}
		p := PublicItem(i)
		if strings.Contains(p.DisplayPath, unsafe) || PublicItem(p).DisplayPath != p.DisplayPath {
			t.Fatal("unsafe or non-idempotent public projection")
		}
		p = PublicItem(Item{DisplayPath: "~/…/arch" + unsafe + "ive.bak"})
		if strings.Contains(p.DisplayPath, unsafe) {
			t.Fatal("already projected path bypassed scrub")
		}
	}
	if strings.Contains(PublicItem(Item{DisplayPath: "~/…/password=example"}).DisplayPath, "example") {
		t.Fatal("display basename bypassed redaction")
	}
}

func TestPublicNoAtimeSkipNoticeSurvivesSafeProjection(t *testing.T) {
	r := PublicReport(Report{Partial: true, Notices: []string{"reviewed-root-1 skipped: no O_NOATIME permission", "/private/path"}})
	if !strings.Contains(strings.Join(r.Notices, " "), "skipped: no O_NOATIME permission") || strings.Contains(strings.Join(r.Notices, " "), "/private/path") {
		t.Fatal(r.Notices)
	}
}

func contractFixture() Report {
	return Report{Schema: "disk-deep/v1", Items: []Item{{ID: "candidate-1", PrivatePath: "/tmp/archive.bak", Category: "app-update-backups", LastUsedSource: "atime", Confidence: "low", SuggestedAction: "investigate", EvidenceStrength: "weak"}}}
}

func TestDecodeStrictItemIdentifiersTimestampsAndSources(t *testing.T) {
	for _, id := range []string{"", "candidate/name", "candidate.name", "with space", "candidate\u202e", "candidate\x1b", strings.Repeat("a", 129)} {
		r := contractFixture()
		r.Items[0].ID = id
		raw, _ := json.Marshal(r)
		if _, _, err := Decode(raw); err == nil {
			t.Fatalf("unsafe ID accepted: %q", id)
		}
	}
	for _, stamp := range []string{"not a time", "2026-10-01T12:00:00.000Z", "2026-10-01T12:00:00.120Z", "2026-10-01T12:00:00+00:00", "2026-10-01T12:00:00Z\u200b", "2026-10-01T12:00:00,12Z"} {
		r := contractFixture()
		r.Items[0].LastUsed = stamp
		raw, _ := json.Marshal(r)
		if _, _, err := Decode(raw); err == nil {
			t.Fatalf("noncanonical last_used accepted: %q", stamp)
		}
	}
	for _, source := range []string{"/private/path", "atime\x1b", "atime\u202e", strings.Repeat("a", 10000)} {
		r := contractFixture()
		r.Items[0].LastUsedSource = source
		raw, _ := json.Marshal(r)
		if _, _, err := Decode(raw); err == nil {
			t.Fatalf("unreviewed source accepted: %q", source)
		}
	}
	for _, stamp := range []string{"", "2026-10-01T12:00:00Z", "2026-10-01T12:00:00.12Z", "2026-10-01T12:00:00.123456789Z", "2026-10-01T12:00:00+05:00"} {
		for _, source := range []string{"", "unknown", "atime", "all-container references", "process start ticks"} {
			r := contractFixture()
			r.Items[0].LastUsed = stamp
			r.Items[0].LastUsedSource = source
			raw, _ := json.Marshal(r)
			if _, _, err := Decode(raw); err != nil {
				t.Fatalf("legitimate evidence rejected: %q %q: %v", stamp, source, err)
			}
		}
	}
}

func TestStoredFreeTextAndLegacyEvidenceScrubbed(t *testing.T) {
	i := StoredItem(Item{ID: "candidate\u202e", PrivatePath: "/tmp/old.bak", LastUsed: "2026-10-01T12:00:00Z\u200b", LastUsedSource: "atime\x1b", OwnerApp: "app\u200d", AgeBucket: "old\u2066", ExclusionReason: "reason\x00"})
	if i.ID != "item" || i.LastUsed != "" || i.LastUsedSource != "unknown" {
		t.Fatal("unsafe legacy evidence projected", i)
	}
	for _, text := range []string{i.OwnerApp, i.AgeBucket, i.ExclusionReason} {
		if strings.ContainsAny(text, "\u200d\u2066\x00") {
			t.Fatalf("unsafe free text %q", text)
		}
	}
	r := StoredReport(Report{Notices: []string{"notice\u202e"}, InaccessibleRoots: []string{"root\x1b"}, Excluded: map[string]Aggregate{"reason\u200b": {Count: 1}}, PolicyID: "policy\u2066"})
	raw, _ := json.Marshal(r)
	if strings.ContainsAny(string(raw), "\u202e\u200b\u2066") || strings.Contains(string(raw), `\u001b`) {
		t.Fatal("unsafe report metadata", string(raw))
	}
}
