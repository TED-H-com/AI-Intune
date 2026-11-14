package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"text/template/parse"
)

// TestEveryTemplateIsRendered fails for a template that no page reaches: production
// Go code must name the template, or a template that calls it.
func TestEveryTemplateIsRendered(t *testing.T) {
	parsed, err := parseTemplates()
	if err != nil {
		t.Fatalf("parseTemplates: %v", err)
	}

	checked := make(map[string]*template.Template)
	candidateNames := make(map[string]bool)
	edges := make(map[string][]string)

	for _, tmpl := range parsed.Templates() {
		name := tmpl.Name()
		if name == "" {
			continue
		}
		if !isWhitespaceOnlyTree(tmpl.Tree) {
			checked[name] = tmpl
			candidateNames[name] = true
		}
		calls := templateCalls(tmpl.Tree)
		if len(calls) > 0 {
			edges[name] = calls
			candidateNames[name] = true
			for _, callee := range calls {
				candidateNames[callee] = true
			}
		}
	}

	repoRoot := findRepoRoot(t)
	roots, goFiles, err := renderedTemplateNames(repoRoot, candidateNames)
	if err != nil {
		t.Fatalf("renderedTemplateNames: %v", err)
	}

	t.Logf("checked %d templates, found %d roots across %d Go files", len(checked), len(roots), goFiles)
	if len(checked) < 90 {
		t.Fatalf("expected at least 90 checked templates, got %d", len(checked))
	}
	if len(roots) < 50 {
		t.Fatalf("expected at least 50 root templates, got %d", len(roots))
	}

	reachable := reachableTemplates(roots, edges)

	var unreachable []string
	for name := range checked {
		if !reachable[name] {
			unreachable = append(unreachable, name)
		}
	}
	sort.Strings(unreachable)

	for _, name := range unreachable {
		tmpl := checked[name]
		parseName := ""
		if tmpl.Tree != nil {
			parseName = tmpl.Tree.ParseName
		}
		t.Errorf("template %q (defined in %s) is not rendered by any page", name, parseName)
	}
}

// isWhitespaceOnlyTree reports a file template that only holds {{define}} blocks.
func isWhitespaceOnlyTree(tree *parse.Tree) bool {
	if tree == nil || tree.Root == nil {
		return true
	}
	for _, node := range tree.Root.Nodes {
		text, ok := node.(*parse.TextNode)
		if !ok || strings.TrimSpace(string(text.Text)) != "" {
			return false
		}
	}
	return true
}

func templateCalls(tree *parse.Tree) []string {
	if tree == nil || tree.Root == nil {
		return nil
	}
	var calls []string
	walkTemplateCalls(tree.Root, &calls)
	return calls
}

func walkTemplateCalls(node parse.Node, calls *[]string) {
	if node == nil {
		return
	}
	switch n := node.(type) {
	case *parse.ListNode:
		if n == nil {
			return
		}
		for _, child := range n.Nodes {
			walkTemplateCalls(child, calls)
		}
	case *parse.TemplateNode:
		*calls = append(*calls, n.Name)
	case *parse.IfNode:
		walkTemplateCalls(n.List, calls)
		walkTemplateCalls(n.ElseList, calls)
	case *parse.RangeNode:
		walkTemplateCalls(n.List, calls)
		walkTemplateCalls(n.ElseList, calls)
	case *parse.WithNode:
		walkTemplateCalls(n.List, calls)
		walkTemplateCalls(n.ElseList, calls)
	}
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}

// renderedTemplateNames returns the candidates that non-test Go code in the
// repository spells out as a string literal, and the number of Go files read.
func renderedTemplateNames(repoRoot string, candidates map[string]bool) (map[string]bool, int, error) {
	roots := make(map[string]bool)
	goFiles := 0
	fset := token.NewFileSet()

	err := filepath.WalkDir(repoRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "testdata", "node_modules":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") || strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		goFiles++
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			val, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if candidates[val] {
				roots[val] = true
			}
			return true
		})
		return nil
	})
	return roots, goFiles, err
}

func reachableTemplates(roots map[string]bool, edges map[string][]string) map[string]bool {
	reachable := make(map[string]bool, len(roots))
	queue := make([]string, 0, len(roots))
	for root := range roots {
		reachable[root] = true
		queue = append(queue, root)
	}
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		for _, next := range edges[curr] {
			if !reachable[next] {
				reachable[next] = true
				queue = append(queue, next)
			}
		}
	}
	return reachable
}
