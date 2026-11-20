// SPDX-License-Identifier: GPL-2.0-or-later

// Package repotest is for tests that hold a file of this repository to the
// Go code: a shell script that must stay self-contained on the device, or
// a document that states a value. Such a file cannot import the code, so a
// test reads it and fails when the two disagree. Import it from _test
// files only. It imports nothing from this module.
package repotest

import (
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// Root is the repository's root: the directory with go.mod, found by
// walking up from the test's working directory (its package directory).
func Root(t testing.TB) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("repotest: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		up := filepath.Dir(dir)
		if up == dir {
			t.Fatalf("repotest: no go.mod above the working directory")
		}
		dir = up
	}
}

// Read is the text of the file at rel, a slash-separated path from the
// repository's root.
func Read(t testing.TB, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(Root(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("repotest: %v", err)
	}
	return string(b)
}

// MustContain fails the test unless the file at rel has phrase.
func MustContain(t testing.TB, rel, phrase string) {
	t.Helper()
	if !strings.Contains(Read(t, rel), phrase) {
		t.Errorf("%s does not have %q", rel, phrase)
	}
}

// ShellVar is the value the shell script text gives name in its first
// top-level assignment: a line that starts in column 0 with assignments
// (NAME=value, several to a line allowed). The value comes without its
// quotes and without a trailing comment; a value that is one
// ${ENV:-default} is its default. Other references ($DIR/bin) are left as
// written, for Expand. The test fails when text has no such assignment.
func ShellVar(t testing.TB, text, name string) string {
	t.Helper()
	v, ok := shellVar(text, name)
	if !ok {
		t.Fatalf("repotest: no top-level %s= in the script", name)
	}
	return v
}

func shellVar(text, name string) (string, bool) {
	for _, line := range strings.Split(text, "\n") {
		if line == "" || line[0] == ' ' || line[0] == '\t' || line[0] == '#' {
			continue
		}
		for _, w := range shellWords(line) {
			n, v, ok := strings.Cut(w, "=")
			if !ok || !shellName(n) {
				break // the command's own words: no more assignments
			}
			if n == name {
				return paramDefault(unquote(v)), true
			}
		}
	}
	return "", false
}

// ShellFunc is the definition of the function name in the shell script
// text, from its "name() {" line in column 0 to the "}" that closes it in
// column 0 (the same line for a one-line function), with a newline at the
// end: what sh needs to define it. The test fails when text has none.
func ShellFunc(t testing.TB, text, name string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, name+"() {") {
			continue
		}
		if strings.HasSuffix(strings.TrimRight(l, " \t"), "}") {
			return l + "\n"
		}
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == "}" {
				return strings.Join(lines[i:j+1], "\n") + "\n"
			}
		}
	}
	t.Fatalf("repotest: no function %s() in the script", name)
	return ""
}

// ShellFuncVar is ShellVar for a function's own statements: the value the
// function fn of the script text gives name in its first assignment among
// the lines indented by one tab (not those nested deeper).
func ShellFuncVar(t testing.TB, text, fn, name string) string {
	t.Helper()
	var body []string
	for _, l := range strings.Split(ShellFunc(t, text, fn), "\n") {
		if strings.HasPrefix(l, "\t") {
			body = append(body, l[1:])
		}
	}
	v, ok := shellVar(strings.Join(body, "\n"), name)
	if !ok {
		t.Fatalf("repotest: %s() has no %s= among its own statements", fn, name)
	}
	return v
}

// Header is what a script's usage prints: its leading comment block from
// line first (counted from 1) to the last line before one that is not a
// comment, each line without its "# " and with a newline at the end.
func Header(text string, first int) string {
	var b strings.Builder
	for i, l := range strings.Split(text, "\n") {
		if i+1 < first {
			continue
		}
		if !strings.HasPrefix(l, "#") {
			break
		}
		l = strings.TrimPrefix(l, "#")
		b.WriteString(strings.TrimPrefix(l, " "))
		b.WriteByte('\n')
	}
	return b.String()
}

// Heredoc is the body of the first here-document of the script text whose
// delimiter is tag (<<tag or <<'tag'), without the line that ends it. The
// body is as written: see HeredocText for what the shell makes of an
// unquoted one. The test fails when text has none.
func Heredoc(t testing.TB, text, tag string) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	for i, l := range lines {
		if !opensHeredoc(l, "<<'"+tag+"'") && !opensHeredoc(l, "<<"+tag) {
			continue
		}
		for j := i + 1; j < len(lines); j++ {
			if lines[j] == tag {
				return strings.Join(lines[i+1:j], "\n")
			}
		}
	}
	t.Fatalf("repotest: no here-document <<%s in the script", tag)
	return ""
}

// opensHeredoc reports whether line has the redirection op as a whole
// word's end: followed by nothing, a blank or the end of a command.
func opensHeredoc(line, op string) bool {
	for rest := line; ; {
		i := strings.Index(rest, op)
		if i < 0 {
			return false
		}
		rest = rest[i+len(op):]
		if rest == "" || strings.IndexByte(" \t;|&)", rest[0]) >= 0 {
			return true
		}
	}
}

// HeredocText is what the shell makes of an unquoted here-document's body:
// \$, \` and \\ are that character, and $NAME or ${NAME} is vars[NAME].
// unknown lists the names referenced that vars does not have (left as
// written), so a caller can refuse a body it cannot render in full. Any
// other use of $ that is not escaped (a command substitution, a
// ${NAME:-default}) is not rendered: it is left as written and reported
// as the unknown name "$".
func HeredocText(body string, vars map[string]string) (text string, unknown []string) {
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c == '\\' && i+1 < len(body) && strings.IndexByte("$`\\", body[i+1]) >= 0 {
			i++
			b.WriteByte(body[i])
			continue
		}
		if c != '$' {
			b.WriteByte(c)
			continue
		}
		j, braced := i+1, false
		if j < len(body) && body[j] == '{' {
			j, braced = j+1, true
		}
		k := j
		for k < len(body) && shellName(body[j:k+1]) {
			k++
		}
		n := body[j:k]
		if braced && (k == len(body) || body[k] != '}') {
			n = ""
		}
		v, ok := vars[n]
		if n == "" || !ok {
			if n == "" {
				n = "$"
			}
			unknown = append(unknown, n)
			b.WriteByte(c)
			continue
		}
		b.WriteString(v)
		if braced {
			k++
		}
		i = k - 1
	}
	return b.String(), unknown
}

// Markdown lists the repository's Markdown files as slash-separated paths
// from its root, sorted.
func Markdown(t testing.TB) []string {
	t.Helper()
	root := Root(t)
	var out []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == ".git" || rel == "dist" {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".md") {
			out = append(out, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("repotest: %v", err)
	}
	sort.Strings(out)
	return out
}

// Expand replaces $NAME and ${NAME} in s with vars[NAME], and
// ${NAME:-default} with vars[NAME] or, when that is empty or missing, the
// expanded default. A plain reference to a name vars does not have is left
// as written, so a failing comparison shows it.
func Expand(s string, vars map[string]string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '$' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		if s[i+1] == '{' {
			end := closing(s, i+1)
			if end < 0 {
				b.WriteByte(s[i])
				continue
			}
			in := s[i+2 : end]
			n, def, hasDef := strings.Cut(in, ":-")
			switch v, ok := vars[n]; {
			case ok && v != "":
				b.WriteString(v)
			case hasDef:
				b.WriteString(Expand(def, vars))
			case ok:
			default:
				b.WriteString(s[i : end+1])
			}
			i = end
			continue
		}
		j := i + 1
		for j < len(s) && shellName(s[i+1:j+1]) {
			j++
		}
		n := s[i+1 : j]
		if v, ok := vars[n]; ok && n != "" {
			b.WriteString(v)
		} else {
			b.WriteString(s[i:j])
		}
		i = j - 1
	}
	return b.String()
}

// Fenced is the body of the n-th (from 0) fenced code block of Markdown
// text whose fence names lang ("" for a fence that names none), without
// the fence lines and with the fence's indentation taken off each line.
// ok is false when text has no such block.
func Fenced(text, lang string, n int) (body string, ok bool) {
	lines := strings.Split(text, "\n")
	for i := 0; i < len(lines); i++ {
		indent, info, isFence := fenceLine(lines[i])
		if !isFence {
			continue
		}
		var got []string
		closed := false
		for i++; i < len(lines); i++ {
			if _, rest, f := fenceLine(lines[i]); f && rest == "" {
				closed = true
				break
			}
			got = append(got, strings.TrimPrefix(lines[i], indent))
		}
		if !closed || info != lang {
			continue
		}
		if n == 0 {
			return strings.Join(got, "\n"), true
		}
		n--
	}
	return "", false
}

// fenceLine reads a ``` fence line: its indentation and what follows the
// backticks.
func fenceLine(l string) (indent, info string, ok bool) {
	t := strings.TrimLeft(l, " \t")
	if !strings.HasPrefix(t, "```") {
		return "", "", false
	}
	return l[:len(l)-len(t)], strings.TrimSpace(strings.TrimLeft(t, "`")), true
}

func shellName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// shellWords splits one line the way sh does: blanks separate words,
// quotes and $( ) or ${ } keep theirs, a # at the start of a word begins
// a comment and a ; ends the command (the words after it are not
// returned). The words keep their quotes.
func shellWords(line string) []string {
	var words []string
	var cur strings.Builder
	in := false // a word is open
	end := func() {
		if in {
			words = append(words, cur.String())
			cur.Reset()
			in = false
		}
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case c == ' ' || c == '\t':
			end()
			continue
		case c == '#' && !in, c == ';':
			end()
			return words
		}
		in = true
		switch {
		case c == '\\' && i+1 < len(line):
			cur.WriteString(line[i : i+2])
			i++
		case c == '\'' || c == '"':
			j := closingQuote(line, i)
			cur.WriteString(line[i : j+1])
			i = j
		case c == '$' && i+1 < len(line) && (line[i+1] == '(' || line[i+1] == '{'):
			j := closing(line, i+1)
			if j < 0 {
				j = len(line) - 1
			}
			cur.WriteString(line[i : j+1])
			i = j
		default:
			cur.WriteByte(c)
		}
	}
	end()
	return words
}

// closingQuote is the index of the quote that closes the one at s[i] (the
// last byte when it is not closed).
func closingQuote(s string, i int) int {
	q := s[i]
	for j := i + 1; j < len(s); j++ {
		switch {
		case s[j] == '\\' && q == '"':
			j++
		case s[j] == q:
			return j
		}
	}
	return len(s) - 1
}

// closing is the index of the bracket that closes the ( or { at s[i], -1
// when it is not closed. Quotes inside are skipped.
func closing(s string, i int) int {
	open, shut := s[i], byte(')')
	if open == '{' {
		shut = '}'
	}
	depth := 0
	for j := i; j < len(s); j++ {
		switch s[j] {
		case '\\':
			j++
		case '\'', '"':
			j = closingQuote(s, j)
		case open:
			depth++
		case shut:
			if depth--; depth == 0 {
				return j
			}
		}
	}
	return -1
}

// unquote takes the quotes off a shell word; $ references stay as written.
func unquote(w string) string {
	var b strings.Builder
	for i := 0; i < len(w); i++ {
		switch c := w[i]; {
		case c == '\\' && i+1 < len(w):
			i++
			b.WriteByte(w[i])
		case c == '\'':
			j := closingQuote(w, i)
			b.WriteString(strings.TrimSuffix(w[i+1:j+1], "'"))
			i = j
		case c == '"':
			j := closingQuote(w, i)
			in := strings.TrimSuffix(w[i+1:j+1], `"`)
			for k := 0; k < len(in); k++ {
				if in[k] == '\\' && k+1 < len(in) && strings.IndexByte("\\\"$`", in[k+1]) >= 0 {
					k++
				}
				b.WriteByte(in[k])
			}
			i = j
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// paramDefault is the default of a value that is one ${NAME:-default}
// (itself resolved the same way); any other value is returned as it is.
func paramDefault(v string) string {
	for strings.HasPrefix(v, "${") && closing(v, 1) == len(v)-1 {
		n, def, ok := strings.Cut(v[2:len(v)-1], ":-")
		if !ok || !shellName(n) {
			break
		}
		v = def
	}
	return v
}
