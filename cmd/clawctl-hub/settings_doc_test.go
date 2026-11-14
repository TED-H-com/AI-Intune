package main

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// hubSettingsDocument is the operator reference for the flags of
// clawctl-hub serve and the environment variables the Hub reads.
const hubSettingsDocument = "docs/HUB-SETTINGS.md"

// environmentNotSetByOperators lists the variables Go code reads that the
// operating system or systemd sets and no Markdown file names, with who sets
// each one.
var environmentNotSetByOperators = map[string]string{
	"MAINPID":      "systemd",
	"WATCHDOG_PID": "systemd",
	"SHELL":        "the login of the account the probe reads",
}

// environmentReadByExpression lists the reads whose variable name is not a
// constant, by file and expression, with where the name comes from.
var environmentReadByExpression = map[string]string{
	"internal/secrets/secrets.go: u.Host": "the variable an env:// secret reference names",
}

// environmentReadThroughGetter lists the calls that pass os.Getenv to a
// function, by file and callee, with the variables that function reads. A
// variable added inside one of those functions needs an entry here.
var environmentReadThroughGetter = map[string][]string{
	"cmd/clawctl-hub/main.go: blobstore.FromEnv": {
		"R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET", "R2_ENDPOINT", "R2_REGION",
		"S3_ACCOUNT_ID", "S3_ACCESS_KEY_ID", "S3_SECRET_ACCESS_KEY", "S3_BUCKET", "S3_ENDPOINT", "S3_REGION",
	},
	"cmd/clawctl-hub/error_issues.go: errorissues.FromEnv": {
		"ERROR_ISSUES_ENABLED", "ERROR_ISSUES_DRY_RUN", "ERROR_ISSUES_INTERVAL",
		"ERROR_ISSUES_TOKEN_FILE", "ERROR_ISSUES_INTUNE_REPO", "ERROR_ISSUES_BAT_REPO",
	},
}

var (
	settingsFlagCellRE     = regexp.MustCompile("^`--([a-z][a-z0-9-]*)`$")
	settingsVariableCellRE = regexp.MustCompile("^`([A-Za-z_][A-Za-z0-9_]*)`$")
	markdownWordRE         = regexp.MustCompile(`[A-Za-z_][A-Za-z0-9_]*`)
)

// TestHubSettingsDocumentListsEveryServeFlag fails for a flag of
// clawctl-hub serve that the settings document has no row for, a row for a
// flag serve does not define, and a row that pairs a flag with a variable other
// than the one its default reads.
func TestHubSettingsDocumentListsEveryServeFlag(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	flags, problems, err := serveFlags(fset, file)
	if err != nil {
		t.Fatalf("main.go: %v", err)
	}
	for _, problem := range problems {
		t.Error(problem)
	}
	rows := readHubSettingsRows(t)
	if len(flags) < 21 {
		t.Fatalf("found %d serve flags", len(flags))
	}
	t.Logf("checked %d serve flags", len(flags))
	for _, name := range sortedKeys(flags) {
		variable, listed := rows.flags[name]
		if !listed {
			t.Errorf("%s has no row for --%s", hubSettingsDocument, name)
			continue
		}
		if want := flags[name]; want != "" && variable != want {
			t.Errorf("%s pairs --%s with %q; its default reads %s", hubSettingsDocument, name, variable, want)
		}
	}
	for _, name := range sortedKeys(rows.flags) {
		if _, defined := flags[name]; !defined {
			t.Errorf("%s has a row for --%s, which serve does not define", hubSettingsDocument, name)
		}
	}
}

// TestHubSettingsDocumentListsEveryVariable fails for a variable the Hub
// command reads that the settings document has no row for, and for a row whose
// variable the Hub command does not read.
func TestHubSettingsDocumentListsEveryVariable(t *testing.T) {
	reads := readRepositoryEnvironment(t)
	rows := readHubSettingsRows(t)
	hub := map[string]bool{}
	for name, files := range reads.names {
		for _, file := range files {
			if strings.HasPrefix(file, "cmd/clawctl-hub/") {
				hub[name] = true
			}
		}
	}
	for _, site := range reads.getters {
		if strings.HasPrefix(site, "cmd/clawctl-hub/") {
			for _, name := range environmentReadThroughGetter[site] {
				hub[name] = true
			}
		}
	}
	if len(hub) < 45 {
		t.Fatalf("found %d variables read by cmd/clawctl-hub", len(hub))
	}
	t.Logf("checked %d variables read by cmd/clawctl-hub", len(hub))
	for _, name := range sortedKeys(hub) {
		if !rows.variables[name] {
			t.Errorf("%s has no row for %s, which cmd/clawctl-hub reads", hubSettingsDocument, name)
		}
	}
	for _, name := range sortedKeys(rows.variables) {
		if !hub[name] {
			t.Errorf("%s has a row for %s, which cmd/clawctl-hub does not read", hubSettingsDocument, name)
		}
	}
}

// TestEveryEnvironmentVariableIsDocumented fails for a variable that non-test
// Go code reads and no Markdown file names, unless the system sets it, and for
// a read or a getter the lists above do not account for.
func TestEveryEnvironmentVariableIsDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	reads := readRepositoryEnvironment(t)
	if len(reads.names) < 45 {
		t.Fatalf("found %d environment variables", len(reads.names))
	}
	t.Logf("checked %d environment variables read by name, %d by expression and %d getter sites",
		len(reads.names), len(reads.dynamic), len(reads.getters))
	words := map[string]bool{}
	for _, file := range repositoryMarkdownFiles(t, root) {
		text, err := os.ReadFile(filepath.Join(root, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, word := range markdownWordRE.FindAllString(string(text), -1) {
			words[word] = true
		}
	}
	for _, problem := range environmentProblems(reads, words,
		environmentNotSetByOperators, environmentReadByExpression, environmentReadThroughGetter) {
		t.Error(problem)
	}
}

// TestEnvironmentProblems runs the documentation checks on fixed reads.
func TestEnvironmentProblems(t *testing.T) {
	reads := environmentReads{
		names: map[string][]string{
			"DOCUMENTED": {"a.go"}, "UNDOCUMENTED": {"a.go", "b.go"}, "SYSTEM": {"a.go"}, "NAMED_SYSTEM": {"a.go"},
		},
		dynamic: []string{"a.go: key", "a.go: other"},
		getters: []string{"a.go: load", "a.go: unlisted"},
	}
	words := map[string]bool{"DOCUMENTED": true, "NAMED_SYSTEM": true, "GOT_DOCUMENTED": true}
	got := environmentProblems(reads, words,
		map[string]string{"SYSTEM": "", "NAMED_SYSTEM": "", "UNREAD_SYSTEM": ""},
		map[string]string{"a.go: key": "", "a.go: gone": ""},
		map[string][]string{"a.go: load": {"GOT_DOCUMENTED", "GOT_UNDOCUMENTED"}, "a.go: gone": {"GONE"}})
	want := []string{
		"no Markdown file names UNDOCUMENTED, which a.go, b.go reads",
		"environmentNotSetByOperators lists NAMED_SYSTEM, which a Markdown file names",
		"environmentNotSetByOperators lists UNREAD_SYSTEM, which no Go code reads",
		"a.go: other reads a variable whose name is not a constant; list it in environmentReadByExpression",
		`environmentReadByExpression lists "a.go: gone", which no longer occurs`,
		"a.go: unlisted passes os.Getenv or os.LookupEnv; list the variables it reads in environmentReadThroughGetter",
		`environmentReadThroughGetter lists "a.go: gone", which no longer occurs`,
		"no Markdown file names GOT_UNDOCUMENTED, which a.go: load reads",
	}
	if !slices.Equal(got, want) {
		t.Errorf("problems = %q, want %q", got, want)
	}
}

// TestHubSettingsRowParser runs the row parser on a fixed table.
func TestHubSettingsRowParser(t *testing.T) {
	rows, problems := parseHubSettingsRows(strings.Join([]string{
		"| Flag | Variable | Default | Effect |",
		"|---|---|---|---|",
		"| `--alpha` | `ALPHA` | none | a |",
		"| `--beta` | — | none | b |",
		"| `--gamma` |",
		"| `--epsilon` | `EPSILON` | none | no closing pipe",
		"| `--alpha` | `ALPHA` | none | again |",
		"| `DELTA` | serve | none | d |",
		"| `ALPHA` | serve | none | twice |",
		"| `not a flag` | `ZETA` | none | z |",
		"text | `--eta` | `ETA` |",
	}, "\n"))
	if want := map[string]string{"alpha": "ALPHA", "beta": "", "gamma": "", "epsilon": "EPSILON"}; !maps.Equal(rows.flags, want) {
		t.Errorf("flags = %v, want %v", rows.flags, want)
	}
	if want := map[string]bool{"ALPHA": true, "DELTA": true, "EPSILON": true}; !maps.Equal(rows.variables, want) {
		t.Errorf("variables = %v, want %v", rows.variables, want)
	}
	if want := []string{"has two rows for --alpha", "has two rows for ALPHA"}; !slices.Equal(problems, want) {
		t.Errorf("problems = %q, want %q", problems, want)
	}
}

// TestServeFlagCollector runs the flag collector on a fixed source that uses
// every flag.FlagSet method that defines a flag.
func TestServeFlagCollector(t *testing.T) {
	const source = `package main

func serve(argv []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	fs.Bool("bool", os.Getenv("BOOL_ENV") == "1", "")
	fs.String("string", os.Getenv("STRING_ENV"), "")
	fs.Duration("duration", 0, "")
	fs.Int("int", 0, "")
	fs.Int64("int64", 0, "")
	fs.Uint("uint", 0, "")
	fs.Uint64("uint64", 0, "")
	fs.Float64("float64", 0, "")
	fs.Func("func", "", nil)
	fs.BoolFunc("boolfunc", "", nil)
	fs.BoolVar(&b, "boolvar", false, "")
	fs.StringVar(&s, "stringvar", os.Getenv("STRINGVAR_ENV"), "")
	fs.DurationVar(&d, "durationvar", 0, "")
	fs.IntVar(&i, "intvar", 0, "")
	fs.Int64Var(&i64, "int64var", 0, "")
	fs.UintVar(&u, "uintvar", 0, "")
	fs.Uint64Var(&u64, "uint64var", 0, "")
	fs.Float64Var(&f, "float64var", 0, "")
	fs.Var(v, "var", "")
	fs.TextVar(v, "textvar", v, "")
	name := "computed"
	fs.String(name, "", "")
	_ = fs.Parse(argv)
}

func other() {
	fs := flag.NewFlagSet("other", flag.ExitOnError)
	fs.Bool("elsewhere", false, "")
}

func (h hub) serve() {
	fs := flag.NewFlagSet("method", flag.ExitOnError)
	fs.Bool("method", false, "")
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", source, 0)
	if err != nil {
		t.Fatal(err)
	}
	flags, problems, err := serveFlags(fset, file)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"bool": "BOOL_ENV", "string": "STRING_ENV", "stringvar": "STRINGVAR_ENV",
	}
	for _, name := range []string{"duration", "int", "int64", "uint", "uint64", "float64", "func", "boolfunc",
		"boolvar", "durationvar", "intvar", "int64var", "uintvar", "uint64var", "float64var", "var", "textvar"} {
		want[name] = ""
	}
	if !maps.Equal(flags, want) {
		t.Errorf("flags = %v, want %v", flags, want)
	}
	if want := []string{"serve.go:26:2: serve defines a flag whose name is not a literal"}; !slices.Equal(problems, want) {
		t.Errorf("problems = %q, want %q", problems, want)
	}
	for _, broken := range []string{
		"package main\n\nfunc main() {}\n",
		"package main\n\nfunc serve() { fs := newSet(); fs.Bool(\"x\", false, \"\") }\n",
	} {
		file, err := parser.ParseFile(fset, "broken.go", broken, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := serveFlags(fset, file); err == nil {
			t.Errorf("serveFlags(%q) returned no error", broken)
		}
	}
}

// TestEnvironmentReadCollector runs the environment read collector on a fixed
// tree.
func TestEnvironmentReadCollector(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a/a.go", `package a

const named = "NAMED_ENV"

const (
	first = iota
	second
)

var notConst = "VAR_ENV"

func read(key string, load func(func(string) string)) {
	_ = os.Getenv("LITERAL_ENV")
	_, _ = os.LookupEnv(named)
	_ = os.Getenv(named)
	_ = os.Getenv(key)
	_ = os.Getenv(notConst)
	load(os.Getenv)
	load(os.Getenv)
	get := os.LookupEnv
	_ = get
}
`)
	write("b/b.go", `package b

func read() { _ = os.Getenv(named) }
`)
	write("a/a_test.go", `package a

func test() { _ = os.Getenv("TEST_ONLY_ENV") }
`)
	write(".git/hook.go", `package hook

func hook() { _ = os.Getenv("GIT_ENV") }
`)
	reads, err := environmentReadsIn(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := map[string][]string{"LITERAL_ENV": {"a/a.go"}, "NAMED_ENV": {"a/a.go"}}; !maps.EqualFunc(reads.names, want, slices.Equal) {
		t.Errorf("names = %v, want %v", reads.names, want)
	}
	if want := []string{"a/a.go: key", "a/a.go: notConst", "b/b.go: named"}; !slices.Equal(reads.dynamic, want) {
		t.Errorf("dynamic = %q, want %q", reads.dynamic, want)
	}
	if want := []string{"a/a.go: load", "a/a.go: os.LookupEnv"}; !slices.Equal(reads.getters, want) {
		t.Errorf("getters = %q, want %q", reads.getters, want)
	}
}

type hubSettingsRows struct {
	flags     map[string]string // flag name → paired variable, or ""
	variables map[string]bool
}

func readHubSettingsRows(t *testing.T) hubSettingsRows {
	t.Helper()
	text, err := os.ReadFile(filepath.Join("..", "..", hubSettingsDocument))
	if err != nil {
		t.Fatal(err)
	}
	rows, problems := parseHubSettingsRows(string(text))
	for _, problem := range problems {
		t.Errorf("%s %s", hubSettingsDocument, problem)
	}
	return rows
}

// parseHubSettingsRows reads the tables of the settings document. A flag row
// starts with `--name` and may pair a `VARIABLE` in its second cell; a variable
// row starts with `VARIABLE`. It returns a problem for each repeated row.
func parseHubSettingsRows(text string) (hubSettingsRows, []string) {
	rows := hubSettingsRows{flags: map[string]string{}, variables: map[string]bool{}}
	var problems []string
	for _, line := range strings.Split(text, "\n") {
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "| "), " |"), " | ")
		if match := settingsFlagCellRE.FindStringSubmatch(cells[0]); match != nil {
			if _, duplicate := rows.flags[match[1]]; duplicate {
				problems = append(problems, "has two rows for --"+match[1])
			}
			variable := ""
			if len(cells) > 1 {
				if pair := settingsVariableCellRE.FindStringSubmatch(cells[1]); pair != nil {
					variable = pair[1]
					rows.variables[variable] = true
				}
			}
			rows.flags[match[1]] = variable
			continue
		}
		if match := settingsVariableCellRE.FindStringSubmatch(cells[0]); match != nil {
			if rows.variables[match[1]] {
				problems = append(problems, "has two rows for "+match[1])
			}
			rows.variables[match[1]] = true
		}
	}
	return rows, problems
}

// serveFlags returns the flags func serve in file defines, each with the
// variable its default reads by name, or "", and a problem for each flag whose
// name is not a literal.
func serveFlags(fset *token.FileSet, file *ast.File) (map[string]string, []string, error) {
	var serve *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv == nil && fn.Name.Name == "serve" {
			serve = fn
		}
	}
	if serve == nil {
		return nil, nil, errors.New("no func serve")
	}
	set := ""
	ast.Inspect(serve.Body, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			call, isCall := assign.Rhs[0].(*ast.CallExpr)
			if id, isIdent := assign.Lhs[0].(*ast.Ident); isCall && isIdent && selectorName(call.Fun, "flag") == "NewFlagSet" {
				set = id.Name
			}
		}
		return true
	})
	if set == "" {
		return nil, nil, errors.New("serve makes no flag.NewFlagSet")
	}
	flags := map[string]string{}
	var problems []string
	ast.Inspect(serve.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		nameArg := -1
		switch selectorName(call.Fun, set) {
		case "Bool", "String", "Duration", "Int", "Int64", "Uint", "Uint64", "Float64", "Func", "BoolFunc":
			nameArg = 0
		case "BoolVar", "StringVar", "DurationVar", "IntVar", "Int64Var", "UintVar", "Uint64Var", "Float64Var", "Var", "TextVar":
			nameArg = 1
		}
		if nameArg < 0 {
			return true
		}
		lit, ok := call.Args[nameArg].(*ast.BasicLit)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s: serve defines a flag whose name is not a literal", fset.Position(call.Pos())))
			return true
		}
		name, _ := strconv.Unquote(lit.Value)
		variable := ""
		ast.Inspect(call.Args[nameArg+1], func(n ast.Node) bool {
			if read, ok := n.(*ast.CallExpr); ok && selectorName(read.Fun, "os") == "Getenv" {
				if lit, ok := read.Args[0].(*ast.BasicLit); ok {
					variable, _ = strconv.Unquote(lit.Value)
				}
			}
			return true
		})
		flags[name] = variable
		return true
	})
	return flags, problems, nil
}

type environmentReads struct {
	names   map[string][]string // variable → files that read it
	dynamic []string            // "file: expression" for reads by a non-constant name
	getters []string            // "file: callee" for other uses of os.Getenv or os.LookupEnv
}

func readRepositoryEnvironment(t *testing.T) environmentReads {
	t.Helper()
	reads, err := environmentReadsIn(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return reads
}

// environmentReadsIn finds every os.Getenv and os.LookupEnv call in the
// non-test Go files under root. A name is a string literal or a constant of the
// same directory whose value is one. Every other use of either function is a
// getter site, keyed by the call it is passed to.
func environmentReadsIn(root string) (environmentReads, error) {
	type parsed struct {
		path string
		file *ast.File
	}
	var files []parsed
	consts := map[string]map[string]string{} // directory → constant → value
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() && entry.Name() == ".git" {
			return filepath.SkipDir
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		files = append(files, parsed{relative, file})
		dir := filepath.Dir(relative)
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				value := spec.(*ast.ValueSpec)
				if len(value.Values) != len(value.Names) {
					continue
				}
				for i, name := range value.Names {
					if lit, ok := value.Values[i].(*ast.BasicLit); ok {
						if consts[dir] == nil {
							consts[dir] = map[string]string{}
						}
						consts[dir][name.Name], _ = strconv.Unquote(lit.Value)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		return environmentReads{}, err
	}
	reads := environmentReads{names: map[string][]string{}}
	isReader := func(expr ast.Expr) bool {
		method := selectorName(expr, "os")
		return method == "Getenv" || method == "LookupEnv"
	}
	for _, item := range files {
		called := map[ast.Expr]bool{}
		passed := map[ast.Expr]string{}
		ast.Inspect(item.file, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				called[call.Fun] = true
				for _, arg := range call.Args {
					passed[arg] = exprSource(call.Fun)
				}
			}
			return true
		})
		ast.Inspect(item.file, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && isReader(sel) && !called[sel] {
				callee, ok := passed[sel]
				if !ok {
					callee = exprSource(sel)
				}
				if site := item.path + ": " + callee; !slices.Contains(reads.getters, site) {
					reads.getters = append(reads.getters, site)
				}
				return true
			}
			call, ok := n.(*ast.CallExpr)
			if !ok || !isReader(call.Fun) {
				return true
			}
			name := ""
			switch arg := call.Args[0].(type) {
			case *ast.BasicLit:
				name, _ = strconv.Unquote(arg.Value)
			case *ast.Ident:
				name = consts[filepath.Dir(item.path)][arg.Name]
			}
			if name == "" {
				reads.dynamic = append(reads.dynamic, item.path+": "+exprSource(call.Args[0]))
				return true
			}
			if !slices.Contains(reads.names[name], item.path) {
				reads.names[name] = append(reads.names[name], item.path)
			}
			return true
		})
	}
	return reads, nil
}

// environmentProblems returns a problem for each variable in reads that no
// Markdown word names, unless exempt lists it, for each list entry that no
// longer matches a read, and for each read or getter site the lists do not
// account for.
func environmentProblems(reads environmentReads, words map[string]bool,
	exempt, byExpression map[string]string, throughGetter map[string][]string) []string {
	var problems []string
	for _, name := range sortedKeys(reads.names) {
		if _, system := exempt[name]; !system && !words[name] {
			problems = append(problems, fmt.Sprintf("no Markdown file names %s, which %s reads", name, strings.Join(reads.names[name], ", ")))
		}
	}
	for _, name := range sortedKeys(exempt) {
		if _, read := reads.names[name]; !read {
			problems = append(problems, fmt.Sprintf("environmentNotSetByOperators lists %s, which no Go code reads", name))
		}
		if words[name] {
			problems = append(problems, fmt.Sprintf("environmentNotSetByOperators lists %s, which a Markdown file names", name))
		}
	}
	for _, read := range reads.dynamic {
		if _, known := byExpression[read]; !known {
			problems = append(problems, fmt.Sprintf("%s reads a variable whose name is not a constant; list it in environmentReadByExpression", read))
		}
	}
	for _, read := range sortedKeys(byExpression) {
		if !slices.Contains(reads.dynamic, read) {
			problems = append(problems, fmt.Sprintf("environmentReadByExpression lists %q, which no longer occurs", read))
		}
	}
	for _, site := range reads.getters {
		if _, known := throughGetter[site]; !known {
			problems = append(problems, fmt.Sprintf("%s passes os.Getenv or os.LookupEnv; list the variables it reads in environmentReadThroughGetter", site))
		}
	}
	for _, site := range sortedKeys(throughGetter) {
		if !slices.Contains(reads.getters, site) {
			problems = append(problems, fmt.Sprintf("environmentReadThroughGetter lists %q, which no longer occurs", site))
			continue
		}
		for _, name := range throughGetter[site] {
			if !words[name] {
				problems = append(problems, fmt.Sprintf("no Markdown file names %s, which %s reads", name, site))
			}
		}
	}
	return problems
}

// selectorName returns the selected name of x.Name when x is the identifier
// receiver, or "".
func selectorName(expr ast.Expr, receiver string) string {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == receiver {
		return sel.Sel.Name
	}
	return ""
}

func exprSource(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return exprSource(e.X) + "." + e.Sel.Name
	}
	return "expression"
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
