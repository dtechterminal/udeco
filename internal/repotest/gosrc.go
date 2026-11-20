// SPDX-License-Identifier: GPL-2.0-or-later

package repotest

import (
	"bytes"
	"go/ast"
	"go/constant"
	"go/parser"
	"go/printer"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

// Go source read as text, for tests that hold one piece of code to
// another it cannot call: the names a switch has cases for, against the
// list of names there are.

func parseGo(t testing.TB, rel string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, rel, Read(t, rel), parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("repotest: %v", err)
	}
	return fset, f
}

// StringConsts are the string constants the Go file at rel declares at
// package level with a literal value: name -> value. A constant with any
// other value (a number, an expression) is not listed.
func StringConsts(t testing.TB, rel string) map[string]string {
	t.Helper()
	_, f := parseGo(t, rel)
	out := map[string]string{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i >= len(vs.Values) {
					break
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					continue
				}
				if v, err := strconv.Unquote(lit.Value); err == nil {
					out[n.Name] = v
				}
			}
		}
	}
	return out
}

// IntConsts are the integer constants the Go file at rel declares at
// package level, with or without a type, whose value is written with
// integer literals, the operators << >> | & &^ ^ + - * and the file's own
// such constants: name -> value (`0x4001`, `1 << 24`, `A | B`). A constant
// with any other value (a string, a duration, another package's constant,
// iota) is not listed, nor is one whose value does not fit an int64.
func IntConsts(t testing.TB, rel string) map[string]int64 {
	t.Helper()
	_, f := parseGo(t, rel)
	exprs := map[string]ast.Expr{}
	for _, d := range f.Decls {
		g, ok := d.(*ast.GenDecl)
		if !ok || g.Tok != token.CONST {
			continue
		}
		for _, s := range g.Specs {
			vs := s.(*ast.ValueSpec)
			for i, n := range vs.Names {
				if i < len(vs.Values) {
					exprs[n.Name] = vs.Values[i]
				}
			}
		}
	}
	vals := map[string]constant.Value{}
	var eval func(e ast.Expr) constant.Value
	eval = func(e ast.Expr) constant.Value {
		switch e := e.(type) {
		case *ast.BasicLit:
			if e.Kind == token.INT {
				return constant.MakeFromLiteral(e.Value, token.INT, 0)
			}
		case *ast.ParenExpr:
			return eval(e.X)
		case *ast.Ident:
			return vals[e.Name]
		case *ast.BinaryExpr:
			x, y := eval(e.X), eval(e.Y)
			if x == nil || y == nil {
				return nil
			}
			switch e.Op {
			case token.SHL, token.SHR:
				if n, ok := constant.Uint64Val(y); ok && n < 63 {
					return constant.Shift(x, e.Op, uint(n))
				}
			case token.OR, token.AND, token.AND_NOT, token.XOR, token.ADD, token.SUB, token.MUL:
				return constant.BinaryOp(x, e.Op, y)
			}
		}
		return nil
	}
	// a constant may name one declared after it: go round until nothing new
	for changed := true; changed; {
		changed = false
		for name, e := range exprs {
			if vals[name] != nil {
				continue
			}
			if v := eval(e); v != nil {
				vals[name], changed = v, true
			}
		}
	}
	out := map[string]int64{}
	for name, v := range vals {
		if n, ok := constant.Int64Val(v); ok {
			out[name] = n
		}
	}
	return out
}

// FlagDefaults are the command-line flags the Go file at rel registers
// with the flag package's calls, on the package or on a FlagSet, and the
// default each is given, as written: name -> `":2222"`, `false`,
// `time.Minute`, `defaultModel`. A call counts when it has the shape of
// flag.String(name, default, usage) or flag.StringVar(&v, name, default,
// usage) for one of the flag package's value kinds and names the flag
// with a string literal.
func FlagDefaults(t testing.TB, rel string) map[string]string {
	t.Helper()
	fset, f := parseGo(t, rel)
	out := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		kind, isVar := strings.CutSuffix(sel.Sel.Name, "Var")
		switch kind {
		case "Bool", "Duration", "Float64", "Int", "Int64", "String", "Uint", "Uint64":
		default:
			return true
		}
		at := 0 // the name's place among the arguments
		if isVar {
			at = 1
		}
		if len(call.Args) != at+3 {
			return true
		}
		lit, ok := call.Args[at].(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		name, err := strconv.Unquote(lit.Value)
		if err != nil {
			return true
		}
		var b bytes.Buffer
		printer.Fprint(&b, fset, call.Args[at+1])
		out[name] = b.String()
		return true
	})
	return out
}

// Switch is one expression switch of a function.
type Switch struct {
	Tag   string     // what it switches on, as written ("verb", "r.Cmd"); "" for a switch without a tag
	Cases [][]string // each case clause's expressions as written (`device.ActKick`, `"scan"`); default is not listed
}

// Has reports whether one of the switch's cases names expr.
func (s Switch) Has(expr string) bool {
	for _, c := range s.Cases {
		for _, e := range c {
			if e == expr {
				return true
			}
		}
	}
	return false
}

// Switches are the expression switches in the body of the function or
// method fn of the Go file at rel, nested ones included, in source order.
// The test fails when the file has no such function.
func Switches(t testing.TB, rel, fn string) []Switch {
	t.Helper()
	fset, f := parseGo(t, rel)
	text := func(n ast.Node) string {
		var b bytes.Buffer
		printer.Fprint(&b, fset, n)
		return b.String()
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != fn || fd.Body == nil {
			continue
		}
		var out []Switch
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			s := Switch{}
			if sw.Tag != nil {
				s.Tag = text(sw.Tag)
			}
			for _, c := range sw.Body.List {
				var exprs []string
				for _, e := range c.(*ast.CaseClause).List {
					exprs = append(exprs, text(e))
				}
				if exprs != nil {
					s.Cases = append(s.Cases, exprs)
				}
			}
			out = append(out, s)
			return true
		})
		return out
	}
	t.Fatalf("repotest: no func %s in %s", fn, rel)
	return nil
}

// SwitchOn is the first switch of fn (Switches) whose tag is tag. The
// test fails when there is none.
func SwitchOn(t testing.TB, rel, fn, tag string) Switch {
	t.Helper()
	for _, s := range Switches(t, rel, fn) {
		if s.Tag == tag {
			return s
		}
	}
	t.Fatalf("repotest: func %s in %s has no switch on %s", fn, rel, tag)
	return Switch{}
}

// Consts are the values of the constants the switch's cases name as
// pkg.Name, for the names consts has (StringConsts of the package's
// file). other lists every case expression that is not one of those.
func (s Switch) Consts(pkg string, consts map[string]string) (values, other []string) {
	for _, c := range s.Cases {
		for _, e := range c {
			name, ok := strings.CutPrefix(e, pkg+".")
			if v, known := consts[name]; ok && known {
				values = append(values, v)
			} else {
				other = append(other, e)
			}
		}
	}
	return values, other
}

// Cover fails the test unless every item of all is in handled or in
// exempt and in one of them only, and exempt has nothing all does not
// have. what names the items in the failure ("runner.action").
func Cover(t testing.TB, what string, all, handled, exempt []string) {
	t.Helper()
	in := func(list []string, v string) bool {
		for _, x := range list {
			if x == v {
				return true
			}
		}
		return false
	}
	for _, v := range all {
		switch h, e := in(handled, v), in(exempt, v); {
		case h && e:
			t.Errorf("%s: %q is handled and listed as not handled", what, v)
		case !h && !e:
			t.Errorf("%s: %q is neither handled nor listed as not handled", what, v)
		}
	}
	for _, v := range exempt {
		if !in(all, v) {
			t.Errorf("%s: %q is listed as not handled and is not one of %q", what, v, all)
		}
	}
}
