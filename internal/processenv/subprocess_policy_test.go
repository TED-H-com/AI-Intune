package processenv

import (
	"go/ast"
	"go/build/constraint"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Check source rather than the current build so Linux CI covers Windows paths.
func TestSubprocessesUseProcessenv(t *testing.T) {
	root := filepath.Join("..", "..")
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == ".bat-worktrees" || entry.Name() == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		stem := strings.TrimSuffix(name, ".go")
		parts := strings.Split(stem, "_")
		platform := parts[len(parts)-1]
		if platform == "amd64" || platform == "arm64" || platform == "386" || platform == "arm" {
			if len(parts) > 1 {
				platform = parts[len(parts)-2]
			}
		}
		if platform == "linux" || platform == "darwin" || platform == "unix" {
			return nil
		}

		source, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(source), "\n") {
			if strings.HasPrefix(line, "//go:build ") {
				expr, err := constraint.Parse(line)
				if err != nil {
					return err
				}
				possible, _ := windowsConstraintPossibilities(expr)
				if !possible {
					return nil
				}

				break
			}
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// The central constructor applies HideConsole before returning the command.
		if filepath.ToSlash(rel) == "internal/processenv/processenv.go" {
			return nil
		}
		tree, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			return err
		}
		aliases := map[string]bool{}
		for _, imp := range tree.Imports {
			value, _ := strconv.Unquote(imp.Path.Value)
			if value == "os/exec" {
				alias := "exec"
				if imp.Name != nil {
					alias = imp.Name.Name
				}
				aliases[alias] = true
			}
		}
		ast.Inspect(tree, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fun := call.Fun.(type) {
			case *ast.SelectorExpr:
				pkg, ok := fun.X.(*ast.Ident)
				if ok && aliases[pkg.Name] && (fun.Sel.Name == "Command" || fun.Sel.Name == "CommandContext") {
					t.Errorf("%s: use processenv.CommandContext for windowless Windows subprocesses", rel)
				}
			case *ast.Ident:
				if aliases["."] && (fun.Name == "Command" || fun.Name == "CommandContext") {
					t.Errorf("%s: direct os/exec constructor", rel)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// Unknown feature/architecture tags can be either value. Only exclude a file
// when its constraint cannot hold on Windows, including with custom build tags.
func windowsConstraintPossibilities(expr constraint.Expr) (yes, no bool) {
	switch e := expr.(type) {
	case *constraint.TagExpr:
		switch e.Tag {
		case "windows":
			return true, false
		case "linux", "darwin", "unix", "freebsd", "openbsd", "netbsd", "dragonfly", "solaris", "illumos", "android", "ios", "aix", "plan9", "js", "wasip1":
			return false, true
		default:
			return true, true
		}
	case *constraint.NotExpr:
		yes, no = windowsConstraintPossibilities(e.X)
		return no, yes
	case *constraint.AndExpr:
		xy, xn := windowsConstraintPossibilities(e.X)
		yy, yn := windowsConstraintPossibilities(e.Y)
		return xy && yy, xn || yn
	case *constraint.OrExpr:
		xy, xn := windowsConstraintPossibilities(e.X)
		yy, yn := windowsConstraintPossibilities(e.Y)
		return xy || yy, xn && yn
	}
	return true, true
}
