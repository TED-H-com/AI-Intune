package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	markdownInlineCodeRE = regexp.MustCompile("`[^`]*`")
	markdownLinkRE       = regexp.MustCompile(`\]\(([^)\s]+)[^)]*\)`)
	markdownSchemeRE     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
	// A line number in a document is wrong after the next edit of the file it
	// points into, so documents cite a function, type or constant instead.
	markdownCodeLineRE = regexp.MustCompile(`[\w./-]+\.(?:go|sql|sh|py|ps1|ya?ml|js|css|html):\d+(?:-\d+)?\b|` + "`:\\d+(?:-\\d+)?`")
)

func markdownRelativeLinks(text string) []string {
	var links []string
	inFence := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimLeft(line, " ")
		if strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~") {
			inFence = !inFence
			continue
		}
		if inFence {
			continue
		}
		line = markdownInlineCodeRE.ReplaceAllString(line, "")
		for _, match := range markdownLinkRE.FindAllStringSubmatch(line, -1) {
			target := match[1]
			if markdownSchemeRE.MatchString(target) || strings.HasPrefix(target, "#") || strings.HasPrefix(target, "//") {
				continue
			}
			if i := strings.IndexAny(target, "#?"); i >= 0 {
				target = target[:i]
			}
			if target != "" {
				links = append(links, target)
			}
		}
	}
	return links
}

// resolveMarkdownTarget returns a cleaned path relative to the repository root.
func resolveMarkdownTarget(source, target string) string {
	if strings.HasPrefix(target, "/") {
		return filepath.Clean(filepath.FromSlash(strings.TrimPrefix(target, "/")))
	}
	return filepath.Clean(filepath.Join(filepath.Dir(source), filepath.FromSlash(target)))
}

func TestMarkdownRelativeLinks(t *testing.T) {
	text := strings.Join([]string{
		`[relative](docs/a.md#details?unused) ![image](/docs/icon.png?size=2#preview "caption")`,
		`[scheme](HTTPS://example.com) [email](mailto:a@example.com) [custom](git+ssh:repo) [host](//example.com/file) [fragment](#section) [query](?only)`,
		"`[code](ignored.md)` [next](b.md?foo=1) [titled](c.md \"caption\")",
		"   ```go",
		`[fenced](ignored.md)`,
		"   ```",
		"~~~",
		`[tilde](ignored.md)`,
		"~~~",
		`[last](d.md#anchor)`,
	}, "\n")
	want := []string{"docs/a.md", "/docs/icon.png", "b.md", "c.md", "d.md"}
	if got := markdownRelativeLinks(text); !slices.Equal(got, want) {
		t.Errorf("markdownRelativeLinks() = %q, want %q", got, want)
	}
}

// repositoryMarkdownFiles lists the Markdown files of the repository, relative
// to root.
func repositoryMarkdownFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{"README.md", "README.zh-TW.md", "AGENTS.md", "DESIGN.md"}
	for _, dir := range []string{"docs", "skills", "ops"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || filepath.Ext(path) != ".md" {
				return nil
			}
			relative, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			files = append(files, relative)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", dir, err)
		}
	}
	return files
}

func TestMarkdownRelativeLinksResolve(t *testing.T) {
	root := filepath.Join("..", "..")
	files := repositoryMarkdownFiles(t, root)
	linkCount := 0
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.ToSlash(file), err)
		}
		links := markdownRelativeLinks(string(content))
		linkCount += len(links)
		for _, target := range links {
			resolved := resolveMarkdownTarget(file, target)
			if _, err := os.Stat(filepath.Join(root, resolved)); err != nil {
				t.Errorf("%s: link %q does not resolve", filepath.ToSlash(file), target)
			}
		}
	}
	t.Logf("checked %d Markdown files and %d relative links", len(files), linkCount)
	if len(files) < 70 || linkCount < 300 {
		t.Fatalf("checked too few Markdown files or links: %d files, %d links", len(files), linkCount)
	}
}

func TestDocsIndexListsEveryDocument(t *testing.T) {
	root := filepath.Join("..", "..")
	index := filepath.Join("docs", "README.md")
	content, err := os.ReadFile(filepath.Join(root, index))
	if err != nil {
		t.Fatalf("read %s: %v", filepath.ToSlash(index), err)
	}
	indexed := make(map[string]int)
	for _, target := range markdownRelativeLinks(string(content)) {
		resolved := resolveMarkdownTarget(index, target)
		if filepath.Ext(resolved) != ".md" {
			continue
		}
		indexed[resolved]++
		if indexed[resolved] == 2 {
			t.Errorf("docs/README.md lists %s more than once", filepath.ToSlash(resolved))
		}
		if resolved != "README.md" && !strings.HasPrefix(resolved, "docs"+string(filepath.Separator)) {
			t.Errorf("docs/README.md links %s, which is not a document under docs/", filepath.ToSlash(resolved))
		}
	}

	documentCount := 0
	err = filepath.WalkDir(filepath.Join(root, "docs"), func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || filepath.Ext(path) != ".md" {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if relative == index {
			return nil
		}
		documentCount++
		if indexed[relative] == 0 {
			t.Errorf("docs/README.md does not list %s", filepath.ToSlash(relative))
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk docs: %v", err)
	}

	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	linked := false
	for _, target := range markdownRelativeLinks(string(readme)) {
		if resolveMarkdownTarget("README.md", target) == index {
			linked = true
			break
		}
	}
	if !linked {
		t.Errorf("README.md does not link docs/README.md")
	}
	if documentCount < 50 {
		t.Fatalf("walked too few documents under docs/: %d", documentCount)
	}
}

func TestMarkdownCodeLineReferences(t *testing.T) {
	for _, tc := range []struct {
		text string
		want []string
	}{
		{"`internal/store/deploy.go:982` writes it", []string{"internal/store/deploy.go:982"}},
		{"see internal/store/schema.sql:30-31 and `:547`", []string{"internal/store/schema.sql:30-31", "`:547`"}},
		{"`ops/install-hub.sh:214`, `site/app.js:3`, `.github/workflows/ci.yml:40`",
			[]string{"ops/install-hub.sh:214", "site/app.js:3", ".github/workflows/ci.yml:40"}},
		{"`internal/store/deploy.go` and `Store.RecordVerification`", nil},
		{"`127.0.0.1:8770`, `golang:1.27.4-bookworm`, `ghcr.io/ted-h-com/clawctl-hub:v1`", nil},
		{"`--report-at 08:00`, `http://localhost:8788/`, `file:///var/lib/x/token.env#TOKEN`", nil},
	} {
		if got := markdownCodeLineRE.FindAllString(tc.text, -1); !slices.Equal(got, tc.want) {
			t.Errorf("line references in %q = %q, want %q", tc.text, got, tc.want)
		}
	}
}

func TestMarkdownCitesCodeWithoutLineNumbers(t *testing.T) {
	root := filepath.Join("..", "..")
	files := repositoryMarkdownFiles(t, root)
	for _, file := range files {
		content, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatalf("read %s: %v", filepath.ToSlash(file), err)
		}
		for number, line := range strings.Split(string(content), "\n") {
			for _, reference := range markdownCodeLineRE.FindAllString(line, -1) {
				t.Errorf("%s:%d: %s cites code by line number; cite the function, type or constant instead",
					filepath.ToSlash(file), number+1, reference)
			}
		}
	}
	if len(files) < 70 {
		t.Fatalf("checked too few Markdown files: %d", len(files))
	}
}
