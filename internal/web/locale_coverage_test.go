package web

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// navigationTextFromData lists navigation texts whose values are not fixed in
// source. Each reason names where that value comes from.
var navigationTextFromData = map[string]string{
	"web.go: machine.Item.DisplayName": "machine display name",
}

// TestEnglishNavigationCoversEveryTitleAndLabel fails for a page title or a
// navigation label that the English navigation would show in Chinese. It reads
// every value a composite literal in the package gives one of navTextFields.
func TestEnglishNavigationCoversEveryTitleAndLabel(t *testing.T) {
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(paths)
	fset := token.NewFileSet()
	var files []*ast.File
	sources := map[*ast.File][]byte{}
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
		sources[file] = src
	}

	resolver := newNavResolver(fset, files, sources)
	var exprs []navText
	for _, file := range files {
		exprs = append(exprs, navCollectTexts(fset, file, sources[file])...)
	}

	occurred := map[string]bool{}
	uncheckable := func(text navText) {
		key := text.file + ": " + text.source
		occurred[key] = true
		if _, known := navigationTextFromData[key]; !known {
			t.Errorf("%s: navigation text %s cannot be checked; resolve it or add it to navigationTextFromData", text.where, text.source)
		}
	}
	candidates := 0
	for _, expr := range exprs {
		values, ok := resolver.candidates(expr.expr, expr.fn, false)
		if !ok {
			uncheckable(expr)
			continue
		}
		for _, value := range values {
			candidates++
			english := englishNavigationText(value)
			if navContainsHan(english) {
				t.Errorf("%s: English navigation shows %q for %q", expr.where, english, value)
			}
			if navIsBilingual(value) && strings.Contains(traditionalNavigationText(value), " / ") {
				t.Errorf("%s: Traditional Chinese navigation shows the bilingual source %q", expr.where, value)
			}
		}
	}
	// Assignments, call arguments and return values that reach a navigation text
	// and cannot be resolved need a reason too.
	reported := map[string]bool{}
	for _, text := range resolver.pending {
		if !reported[text.where+" "+text.source] {
			reported[text.where+" "+text.source] = true
			uncheckable(text)
		}
	}
	var stale []string
	for key := range navigationTextFromData {
		if !occurred[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("navigationTextFromData lists %q, which no longer occurs", key)
	}
	t.Logf("expressions=%d candidates=%d", len(exprs), candidates)
	if len(exprs) < 150 || candidates < 250 {
		t.Errorf("collected %d expressions and checked %d candidate strings", len(exprs), candidates)
	}
}

func TestEnglishNavigationPatterns(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"確認撤銷 host-1 的待兌換 enroll 票", "Confirm revoking the pending enrollment ticket for host-1"},
		{"確認 host-1 的 enroll 票", "Confirm the enrollment ticket for host-1"},
		{"確認 host-1 的生命週期變更", "Confirm the lifecycle change for host-1"},
		{"確認 host-1 的診斷", "Confirm diagnostics for host-1"},
		{"確認 fetch tool@1.2.3", "Confirm fetch tool@1.2.3"},
		{"確認 retry deployment", "Confirm retry deployment"},
		{"部署 0b02cd0a", "Deployment 0b02cd0a"},
		{"host-1 的資料", "host-1 data"},
		{"host-1 事件時間軸", "host-1 event timeline"},
		{"host-1 的終端", "host-1 terminal"},
		{"host-1 的 enroll 票", "host-1 enrollment ticket"},
		{"代理程式活動 1a2b3c4d", "Agent activity 1a2b3c4d"},
		{"確認 ", "確認 "},
		{"離線通知", "Offline alerts"},
		{"Checks / 檢查", "Checks"},
	}
	for _, test := range tests {
		t.Run(test.in, func(t *testing.T) {
			if got := englishNavigationText(test.in); got != test.want {
				t.Errorf("englishNavigationText(%q) = %q, want %q", test.in, got, test.want)
			}
		})
	}
}

// TestNavigationTextResolver runs the collector and the resolver on a small
// source: element literals with elided types, a name derived from itself and a
// recursive call.
func TestNavigationTextResolver(t *testing.T) {
	const src = `package web

const home = "首頁"

func pages(name string) []page {
	title := name + " 的資料"
	title = again(title)
	return []page{{Title: title}, page{Title: home}}
}

func again(s string) string { return s }

func depth(n int) string {
	if n == 0 {
		return "根"
	}
	return depth(n - 1)
}

func items() []subNavigationItem {
	return []subNavigationItem{{Label: depth(2)}, {Label: "活動"}}
}

func use() { _ = pages("裝置") }
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "nav.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	sources := map[*ast.File][]byte{file: []byte(src)}
	resolver := newNavResolver(fset, []*ast.File{file}, sources)
	got := map[string][]string{}
	for _, text := range navCollectTexts(fset, file, sources[file]) {
		values, ok := resolver.candidates(text.expr, text.fn, false)
		if !ok {
			t.Errorf("%s: %s did not resolve", text.where, text.source)
		}
		got[text.source] = values
	}
	want := map[string][]string{
		"title":    {"裝置 的資料"},
		"home":     {"首頁"},
		"depth(2)": {"根"},
		`"活動"`:     {"活動"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("resolved %q, want %q", got, want)
	}
	var pending []string
	for _, text := range resolver.pending {
		pending = append(pending, text.source)
	}
	if want := []string{"depth(n - 1)"}; !reflect.DeepEqual(pending, want) {
		t.Errorf("pending %q, want %q", pending, want)
	}
}

type navText struct {
	where, file, source string
	expr                ast.Expr
	fn                  ast.Node
}

// navTextFields are the struct fields the navigation shows: the page title in
// the breadcrumb and window title, the sub-navigation's name and heading, and
// its items.
var navTextFields = map[string][]string{
	"page":              {"Title"},
	"subNavigation":     {"Label", "Title"},
	"subNavigationItem": {"Label"},
}

func navCollectTexts(fset *token.FileSet, file *ast.File, src []byte) []navText {
	var out []navText
	var stack []ast.Node
	ast.Inspect(file, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return false
		}
		var parent ast.Node
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, n)
		fn := navEnclosingFunc(stack)
		node, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, field := range navTextFields[navCompositeKind(node, parent)] {
			if expr := navField(node, field); expr != nil {
				out = append(out, navTextAt(fset, src, expr, fn))
			}
		}
		return true
	})
	return out
}

func navTextAt(fset *token.FileSet, src []byte, expr ast.Expr, fn ast.Node) navText {
	pos := fset.Position(expr.Pos())
	file := filepath.Base(pos.Filename)
	return navText{
		where:  file + ":" + strconv.Itoa(pos.Line),
		file:   file,
		source: navSource(fset, src, expr),
		expr:   expr,
		fn:     fn,
	}
}

func navSource(fset *token.FileSet, src []byte, node ast.Node) string {
	start := fset.Position(node.Pos()).Offset
	end := fset.Position(node.End()).Offset
	if start < 0 || end < start || end > len(src) {
		return ""
	}
	return string(src[start:end])
}

func navEnclosingFunc(stack []ast.Node) ast.Node {
	for i := len(stack) - 1; i >= 0; i-- {
		switch stack[i].(type) {
		case *ast.FuncDecl, *ast.FuncLit:
			return stack[i]
		}
	}
	return nil
}

func navCompositeKind(node *ast.CompositeLit, parent ast.Node) string {
	if name := navNamedType(node.Type); name != "" {
		return name
	}
	if node.Type != nil || parent == nil {
		return ""
	}
	parentLit, ok := parent.(*ast.CompositeLit)
	if !ok {
		return ""
	}
	array, ok := parentLit.Type.(*ast.ArrayType)
	if !ok {
		return ""
	}
	return navNamedType(array.Elt)
}

func navNamedType(expr ast.Expr) string {
	id, ok := expr.(*ast.Ident)
	if !ok {
		return ""
	}
	return id.Name
}

func navField(node *ast.CompositeLit, name string) ast.Expr {
	for _, elt := range node.Elts {
		pair, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		id, ok := pair.Key.(*ast.Ident)
		if ok && id.Name == name {
			return pair.Value
		}
	}
	return nil
}

func navContainsHan(value string) bool {
	for _, r := range value {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

// navIsBilingual reports a source label written as "English / 中文".
func navIsBilingual(value string) bool {
	english, chinese, ok := strings.Cut(value, " / ")
	return ok && !navContainsHan(english) && navContainsHan(chinese)
}

func navPackageConsts(files []*ast.File) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			var prev []ast.Expr
			for _, spec := range gen.Specs {
				value, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				vals := value.Values
				if len(vals) == 0 {
					vals = prev
				} else {
					prev = vals
				}
				if len(vals) == len(value.Names) {
					for i, name := range value.Names {
						out[name.Name] = vals[i]
					}
				} else if len(vals) == 1 {
					for _, name := range value.Names {
						out[name.Name] = vals[0]
					}
				}
			}
		}
	}
	return out
}

type navFuncInfo struct {
	params map[string]bool
	rhs    map[string][]ast.Expr
}

// navResolver turns a navigation text expression into the strings it can hold.
// Every assignment, call argument and return value that reaches the text counts;
// the whole-value ones it cannot resolve are left in pending.
type navResolver struct {
	fset    *token.FileSet
	srcs    map[string][]byte
	consts  map[string]ast.Expr
	decls   map[string][]*ast.FuncDecl
	calls   map[string][]navCall
	funcs   map[ast.Node]*navFuncInfo
	stack   []navFrame
	pending []navText
}

// navFrame is a name being resolved in fn, or, with an empty name, a call of fn
// being resolved.
type navFrame struct {
	fn   ast.Node
	name string
}

// navCall is a call in the package and the function that makes it.
type navCall struct {
	call *ast.CallExpr
	fn   ast.Node
}

// navValues collects distinct candidate strings in first-seen order.
type navValues struct {
	list []string
	seen map[string]bool
}

func (v *navValues) add(values []string) {
	if v.seen == nil {
		v.seen = map[string]bool{}
	}
	for _, value := range values {
		if !v.seen[value] {
			v.seen[value] = true
			v.list = append(v.list, value)
		}
	}
}

func newNavResolver(fset *token.FileSet, files []*ast.File, sources map[*ast.File][]byte) *navResolver {
	r := &navResolver{
		fset:   fset,
		srcs:   map[string][]byte{},
		consts: navPackageConsts(files),
		decls:  map[string][]*ast.FuncDecl{},
		calls:  map[string][]navCall{},
	}
	for _, file := range files {
		r.srcs[fset.Position(file.Pos()).Filename] = sources[file]
		for _, decl := range file.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Body != nil {
				r.decls[fd.Name.Name] = append(r.decls[fd.Name.Name], fd)
			}
		}
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				stack = stack[:len(stack)-1]
				return false
			}
			stack = append(stack, n)
			if call, ok := n.(*ast.CallExpr); ok {
				if name := navCalleeName(call); name != "" {
					r.calls[name] = append(r.calls[name], navCall{call: call, fn: navEnclosingFunc(stack)})
				}
			}
			return true
		})
	}
	return r
}

// unresolved records a whole-value expression that cannot be resolved.
func (r *navResolver) unresolved(expr ast.Expr, fn ast.Node) {
	src := r.srcs[r.fset.Position(expr.Pos()).Filename]
	r.pending = append(r.pending, navTextAt(r.fset, src, expr, fn))
}

// navCalleeName names the function or method a call invokes, or "" for other calls.
func navCalleeName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		return fun.Sel.Name
	}
	return ""
}

// navCalls reports whether call can invoke decl: a method through a selector,
// a function by its bare name.
func navCalls(call *ast.CallExpr, decl *ast.FuncDecl) bool {
	_, selector := call.Fun.(*ast.SelectorExpr)
	return navCalleeName(call) == decl.Name.Name && selector == (decl.Recv != nil)
}

// navParamIndex finds a named parameter's position; variadic reports a final ...T parameter.
func navParamIndex(decl *ast.FuncDecl, name string) (index int, variadic bool) {
	for _, field := range decl.Type.Params.List {
		if len(field.Names) == 0 {
			index++
			continue
		}
		for _, n := range field.Names {
			if n.Name == name {
				_, variadic = field.Type.(*ast.Ellipsis)
				return index, variadic
			}
			index++
		}
	}
	return -1, false
}

// param resolves a parameter from the matching argument of every call of its function.
func (r *navResolver) param(fn ast.Node, name string, operand bool) ([]string, bool) {
	decl, ok := fn.(*ast.FuncDecl)
	if !ok {
		return navOperandFallback(operand)
	}
	index, variadic := navParamIndex(decl, name)
	if index < 0 || variadic {
		return navOperandFallback(operand)
	}
	var sites []navCall
	for _, site := range r.calls[decl.Name.Name] {
		if navCalls(site.call, decl) {
			sites = append(sites, site)
		}
	}
	if len(sites) == 0 {
		return navOperandFallback(operand)
	}
	var out navValues
	for _, site := range sites {
		if index >= len(site.call.Args) {
			return navOperandFallback(operand)
		}
		arg := site.call.Args[index]
		values, ok := r.candidates(arg, site.fn, operand)
		if !ok {
			r.unresolved(arg, site.fn)
			continue
		}
		out.add(values)
	}
	return out.list, true
}

// call resolves a call of a function in the package from its return statements.
func (r *navResolver) call(call *ast.CallExpr, operand bool) ([]string, bool) {
	var decl *ast.FuncDecl
	for _, candidate := range r.decls[navCalleeName(call)] {
		if !navCalls(call, candidate) {
			continue
		}
		if decl != nil {
			return navOperandFallback(operand)
		}
		decl = candidate
	}
	if decl == nil || decl.Type.Results.NumFields() != 1 || r.active(decl, "") {
		return navOperandFallback(operand)
	}
	r.stack = append(r.stack, navFrame{fn: decl})
	defer func() { r.stack = r.stack[:len(r.stack)-1] }()
	var out navValues
	resolved := true
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if !resolved {
			return false
		}
		switch node := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			if len(node.Results) != 1 {
				resolved = false
				return false
			}
			values, ok := r.candidates(node.Results[0], decl, operand)
			if !ok {
				r.unresolved(node.Results[0], decl)
			}
			out.add(values)
		}
		return true
	})
	if !resolved {
		return navOperandFallback(operand)
	}
	return out.list, true
}

func (r *navResolver) candidates(expr ast.Expr, fn ast.Node, operand bool) ([]string, bool) {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			break
		}
		expr = paren.X
	}
	switch node := expr.(type) {
	case *ast.BasicLit:
		if node.Kind != token.STRING {
			return navOperandFallback(operand)
		}
		value, err := strconv.Unquote(node.Value)
		if err != nil {
			return navOperandFallback(operand)
		}
		return []string{value}, true
	case *ast.BinaryExpr:
		if node.Op != token.ADD {
			return navOperandFallback(operand)
		}
		left, lok := r.candidates(node.X, fn, true)
		right, rok := r.candidates(node.Y, fn, true)
		if !lok || !rok {
			return nil, false
		}
		out := navConcat(left, right)
		if len(out) == 0 {
			return nil, false
		}
		return out, true
	case *ast.Ident:
		return r.ident(node.Name, fn, operand)
	case *ast.CallExpr:
		return r.call(node, operand)
	default:
		return navOperandFallback(operand)
	}
}

func navOperandFallback(operand bool) ([]string, bool) {
	if operand {
		return []string{"x"}, true
	}
	return nil, false
}

func navConcat(left, right []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, a := range left {
		for _, b := range right {
			value := a + b
			if seen[value] {
				continue
			}
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// ident resolves a name from the parameter's arguments, the local assignments
// to it, or a package constant.
func (r *navResolver) ident(name string, fn ast.Node, operand bool) ([]string, bool) {
	if r.active(fn, name) {
		// A value derived from itself, such as x = label(x), adds nothing to
		// the values its other assignments give.
		if operand {
			return []string{"x"}, true
		}
		return nil, true
	}
	if fn != nil {
		info := r.funcInfo(fn)
		rhs, assigned := info.rhs[name]
		if info.params[name] || assigned {
			r.stack = append(r.stack, navFrame{fn: fn, name: name})
			defer func() { r.stack = r.stack[:len(r.stack)-1] }()
			var out navValues
			if info.params[name] {
				values, ok := r.param(fn, name, operand)
				if !ok {
					return navOperandFallback(operand)
				}
				out.add(values)
			}
			for _, expr := range rhs {
				values, ok := r.candidates(expr, fn, operand)
				if !ok {
					r.unresolved(expr, fn)
				}
				out.add(values)
			}
			return out.list, true
		}
	}
	expr, ok := r.consts[name]
	if !ok {
		return navOperandFallback(operand)
	}
	r.stack = append(r.stack, navFrame{name: name})
	defer func() { r.stack = r.stack[:len(r.stack)-1] }()
	return r.candidates(expr, nil, operand)
}

func (r *navResolver) active(fn ast.Node, name string) bool {
	for _, frame := range r.stack {
		if frame.fn == fn && frame.name == name {
			return true
		}
	}
	return false
}

func (r *navResolver) funcInfo(fn ast.Node) *navFuncInfo {
	if r.funcs == nil {
		r.funcs = map[ast.Node]*navFuncInfo{}
	}
	if info, ok := r.funcs[fn]; ok {
		return info
	}
	info := &navFuncInfo{
		params: map[string]bool{},
		rhs:    map[string][]ast.Expr{},
	}
	var typ *ast.FuncType
	var body *ast.BlockStmt
	switch node := fn.(type) {
	case *ast.FuncDecl:
		typ, body = node.Type, node.Body
	case *ast.FuncLit:
		typ, body = node.Type, node.Body
	}
	if typ != nil && typ.Params != nil {
		for _, field := range typ.Params.List {
			for _, name := range field.Names {
				info.params[name.Name] = true
			}
		}
	}
	if body != nil {
		ast.Inspect(body, func(n ast.Node) bool {
			if n == nil {
				return false
			}
			if _, ok := n.(*ast.FuncLit); ok {
				return false
			}
			switch node := n.(type) {
			case *ast.AssignStmt:
				if node.Tok == token.ASSIGN || node.Tok == token.DEFINE {
					navAddPairs(info, node.Lhs, node.Rhs)
				}
			case *ast.DeclStmt:
				gen, ok := node.Decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.VAR {
					break
				}
				for _, spec := range gen.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok || len(value.Values) == 0 {
						continue
					}
					lhs := make([]ast.Expr, len(value.Names))
					for i, name := range value.Names {
						lhs[i] = name
					}
					navAddPairs(info, lhs, value.Values)
				}
			}
			return true
		})
	}
	r.funcs[fn] = info
	return info
}

func navAddPairs(info *navFuncInfo, lhs, rhs []ast.Expr) {
	record := func(name string, expr ast.Expr) {
		if name == "_" {
			return
		}
		info.rhs[name] = append(info.rhs[name], expr)
	}
	if len(lhs) == len(rhs) {
		for i, item := range lhs {
			id, ok := item.(*ast.Ident)
			if !ok {
				continue
			}
			record(id.Name, rhs[i])
		}
		return
	}
	// a, b := f() gives every name the call, which the resolver rejects for
	// returning more than one value.
	for _, item := range lhs {
		id, ok := item.(*ast.Ident)
		if !ok {
			continue
		}
		record(id.Name, rhs[0])
	}
}
