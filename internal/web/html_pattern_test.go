package web

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// htmlPatternV checks an HTML pattern attribute against the unicodeSets (v)
// flag rules this repository relies on. Browsers compile pattern with v, and
// an invalid pattern is skipped.
//
// A character class may contain an unescaped "-" only as a range between two
// class characters in ascending code-point order. A class character is one
// unescaped code point other than "\" and "-" and other than the reserved
// characters below. An escape is a literal, not a range endpoint.
//
// The check fails on an unescaped reserved character and on a doubled
// punctuator inside a class:
//
//	( ) [ ] { } / |
//	&& !! ## $$ %% ** ++ ,, .. :: ;; << == >> ?? @@ ^^ `` ~~
//
// Nested classes and set operations are rejected.
func htmlPatternV(pattern string) error {
	runes := []rune(pattern)
	for i := 0; i < len(runes); {
		if runes[i] == '\\' {
			if i+1 >= len(runes) {
				return fmt.Errorf("trailing escape")
			}
			i += 2
			continue
		}
		if runes[i] != '[' {
			i++
			continue
		}
		interior, next, err := htmlPatternClass(runes, i)
		if err != nil {
			return err
		}
		if err := htmlPatternClassV(interior); err != nil {
			return err
		}
		i = next
	}
	return nil
}

func htmlPatternClass(runes []rune, open int) ([]rune, int, error) {
	i := open + 1
	start := i
	for i < len(runes) {
		if runes[i] == '\\' {
			if i+1 >= len(runes) {
				return nil, 0, fmt.Errorf("trailing escape in character class")
			}
			i += 2
			continue
		}
		if runes[i] == ']' {
			return runes[start:i], i + 1, nil
		}
		i++
	}
	return nil, 0, fmt.Errorf("unclosed character class")
}

func htmlPatternClassV(class []rune) error {
	const reserved = "()[]{}/|"
	doubled := map[rune]bool{
		'&': true, '!': true, '#': true, '$': true, '%': true, '*': true, '+': true,
		',': true, '.': true, ':': true, ';': true, '<': true, '=': true, '>': true,
		'?': true, '@': true, '^': true, '`': true, '~': true,
	}
	prevClass := false
	var prev rune
	for i := 0; i < len(class); {
		if class[i] == '\\' {
			if i+1 >= len(class) {
				return fmt.Errorf("trailing escape in character class")
			}
			i += 2
			prevClass = false
			continue
		}
		if i+1 < len(class) && class[i] == class[i+1] && doubled[class[i]] {
			return fmt.Errorf("unescaped %c%c in character class", class[i], class[i])
		}
		if strings.ContainsRune(reserved, class[i]) {
			return fmt.Errorf("unescaped %q in character class", class[i])
		}
		if class[i] == '-' {
			if !prevClass || i+1 >= len(class) || !htmlPatternClassChar(class[i+1]) || prev > class[i+1] {
				return fmt.Errorf("unescaped '-' is not a range between two class characters")
			}
			i += 2
			prevClass = false
			continue
		}
		if !htmlPatternClassChar(class[i]) {
			return fmt.Errorf("unescaped %q in character class", class[i])
		}
		prev = class[i]
		prevClass = true
		i++
	}
	return nil
}

func htmlPatternClassChar(r rune) bool {
	if r == '\\' || r == '-' || strings.ContainsRune("()[]{}/|", r) {
		return false
	}
	return true
}

func TestHTMLPatternAttributesAreValidUnicodeSets(t *testing.T) {
	cases := []struct {
		pattern string
		ok      bool
	}{
		{`[a-zA-Z0-9_\-]{1,64}`, true},
		{`[a-z0-9][a-z0-9\-]{0,62}`, true},
		{`[A-Za-z0-9_\-]{1,16}`, true},
		{`[a-z]`, true},
		{`[A-Z]`, true},
		{`[0-9]{4}`, true},
		{`[\-]`, true},
		{`[a\-z]`, true},
		{`[à-ö]`, true},
		{`abc`, true},
		{`[a-zA-Z0-9_-]{1,64}`, false},
		{`[a-z0-9-]{0,62}`, false},
		{`[A-Za-z0-9_-]{1,16}`, false},
		{`[-a]`, false},
		{`[a-]`, false},
		{`[a-z-]`, false},
		{`[z-a]`, false},
		{`[9-0]`, false},
		{`[(]`, false},
		{`[)]`, false},
		{`[[]`, false},
		{`[{]`, false},
		{`[}]`, false},
		{`[/]`, false},
		{`[|]`, false},
		{`[[a-z]]`, false},
		{`[a&&b]`, false},
		{`[a-z`, false},
	}
	for _, op := range []string{"&&", "!!", "##", "$$", "%%", "**", "++", ",,", "..", "::", ";;", "<<", "==", ">>", "??", "@@", "^^", "``", "~~"} {
		cases = append(cases, struct {
			pattern string
			ok      bool
		}{"[" + op + "]", false})
	}
	for _, tc := range cases {
		err := htmlPatternV(tc.pattern)
		if tc.ok && err != nil {
			t.Errorf("pattern %q: %v", tc.pattern, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("pattern %q was accepted", tc.pattern)
		}
	}

	seen := map[string]int{}
	note := func(path, pattern string) {
		t.Helper()
		seen[pattern]++
		if err := htmlPatternV(pattern); err != nil {
			t.Errorf("%s: pattern %q: %v", path, pattern, err)
		}
	}
	paths, err := fs.Glob(templateFS, "templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range paths {
		raw, err := templateFS.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		for _, match := range htmlPatternAttribute.FindAllSubmatch(raw, -1) {
			note(path, string(match[1]))
		}
	}
	roots := []string{"../../cmd", ".."}
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					return true
				}
				for _, match := range htmlPatternAttribute.FindAllStringSubmatch(value, -1) {
					note(path, match[1])
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{
		`[a-zA-Z0-9_\-]{1,64}`,
		`[a-z0-9][a-z0-9\-]{0,62}`,
		`[A-Za-z0-9_\-]{1,16}`,
	} {
		if seen[want] == 0 {
			t.Errorf("did not collect pattern %q", want)
		}
	}
}

var htmlPatternAttribute = regexp.MustCompile(`pattern="([^"]*)"`)
