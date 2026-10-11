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
