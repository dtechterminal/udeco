// SPDX-License-Identifier: GPL-2.0-or-later

package repotest

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRootAndRead(t *testing.T) {
	root := Root(t)
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("Root() = %s: %v", root, err)
	}
	if got := Read(t, "go.mod"); !strings.HasPrefix(got, "module ") {
		t.Errorf("Read(go.mod) starts %q", got[:min(len(got), 20)])
	}
	if got := Read(t, "internal/repotest/repotest.go"); !strings.Contains(got, "package repotest") {
		t.Error("Read of a nested path did not return this package's source")
	}
	MustContain(t, "go.mod", "module ")
}

// fatal records what a helper reported instead of ending the test.
type fatal struct {
	testing.TB
	msg string
}

func (f *fatal) Helper()                   {}
func (f *fatal) Errorf(s string, a ...any) { f.msg = s }
func (f *fatal) Fatalf(s string, a ...any) { f.msg = s; panic(f) }

// reported runs fn and returns what it reported through f.
func reported(fn func(testing.TB)) (msg string) {
	f := &fatal{}
	defer func() {
		if r := recover(); r != nil && r != any(f) {
			panic(r)
		}
		msg = f.msg
	}()
	fn(f)
	return f.msg
}

func TestMustContainFails(t *testing.T) {
	if msg := reported(func(tb testing.TB) { MustContain(tb, "go.mod", "no such phrase in go.mod") }); msg == "" {
		t.Error("MustContain did not fail for a phrase the file does not have")
	}
}

const script = `#!/bin/sh
# DIR=/a/comment
DIR=/tp_data/udeco
BIN=$DIR/udeco-ap
KEY=${DECO_KEY:-$HOME/.ssh/deco_x20}
PW=${JIO_TELNET_PW:-${GPW:-}}
D="${UDECO_D:-/flash2/udeco}"
MARK='# udeco-ap supervise (deploy/deco-ap.sh)'
LINE="[ -f $START ] && sh $START </dev/null & $MARK"
GZ_ABOVE=$((6 << 20)) # ship gzip only when the stripped binary is larger
MIN_FREE_KB=1024      # /tp_data free after the install
host=$ALLOWED_HOST ucg=192.168.0.1 port=18080
force_host=0 no_start=0
empty= other=x
ESC=a\ b
Q="say \"hi\" for \$1"
A=1; B=2
GOOS=linux GOARCH=arm go build ./...
	INDENTED=no
if [ "$x" = 1 ]; then NESTED=no; fi
DIR=/second/assignment
`

func TestShellVar(t *testing.T) {
	for name, want := range map[string]string{
		"DIR":         "/tp_data/udeco", // the first assignment, not the comment's
		"BIN":         "$DIR/udeco-ap",
		"KEY":         "$HOME/.ssh/deco_x20",
		"PW":          "",
		"D":           "/flash2/udeco",
		"MARK":        "# udeco-ap supervise (deploy/deco-ap.sh)",
		"LINE":        "[ -f $START ] && sh $START </dev/null & $MARK",
		"GZ_ABOVE":    "$((6 << 20))",
		"MIN_FREE_KB": "1024",
		"host":        "$ALLOWED_HOST",
		"ucg":         "192.168.0.1",
		"port":        "18080",
		"no_start":    "0",
		"empty":       "",
		"other":       "x",
		"ESC":         "a b",
		"Q":           `say "hi" for $1`,
		"A":           "1",
		"GOARCH":      "arm",
	} {
		if got := ShellVar(t, script, name); got != want {
			t.Errorf("ShellVar(%s) = %q, want %q", name, got, want)
		}
	}
	// not top-level assignments
	for _, name := range []string{"INDENTED", "NESTED", "B", "x", "START", "UDECO_D"} {
		if msg := reported(func(tb testing.TB) { ShellVar(tb, script, name) }); msg == "" {
			t.Errorf("ShellVar(%s) did not fail", name)
		}
	}
}

func TestExpand(t *testing.T) {
	vars := map[string]string{"DIR": "/tp_data/udeco", "EMPTY": "", "N": "7"}
	for in, want := range map[string]string{
		"$DIR/udeco-ap":             "/tp_data/udeco/udeco-ap",
		"${DIR}.gz":                 "/tp_data/udeco.gz",
		"a$N$N":                     "a77",
		"${D:-/flash2}/x":           "/flash2/x",
		"${DIR:-/flash2}/x":         "/tp_data/udeco/x",
		"${EMPTY:-fallback}":        "fallback",
		"${EMPTY}|":                 "|",
		"${A:-${B:-$DIR}}":          "/tp_data/udeco",
		"$HOME/.ssh":                "$HOME/.ssh", // not in vars: left as written
		"${HOME}/x":                 "${HOME}/x",
		"cost $5, 100%$":            "cost $5, 100%$",
		"$(date) $((1 + 2)) ${open": "$(date) $((1 + 2)) ${open",
	} {
		if got := Expand(in, vars); got != want {
			t.Errorf("Expand(%q) = %q, want %q", in, got, want)
		}
	}
}

const doc = "# Title\n\n```sh\nmake one\n```\n\ntext\n\n```\nplain\n```\n\n" +
	"1. step\n   ```json\n   {\n     \"a\": 1\n   }\n   ```\n\n```sh\nmake two\nmake three\n```\n\n```go\nunclosed\n"

func TestFenced(t *testing.T) {
	for _, c := range []struct {
		lang string
		n    int
		want string
		ok   bool
	}{
		{"sh", 0, "make one", true},
		{"sh", 1, "make two\nmake three", true},
		{"sh", 2, "", false},
		{"", 0, "plain", true},
		{"", 1, "", false},
		{"json", 0, "{\n  \"a\": 1\n}", true},
		{"go", 0, "", false}, // never closed
		{"yaml", 0, "", false},
	} {
		got, ok := Fenced(doc, c.lang, c.n)
		if got != c.want || ok != c.ok {
			t.Errorf("Fenced(%q, %d) = %q, %v, want %q, %v", c.lang, c.n, got, ok, c.want, c.ok)
		}
	}
}
