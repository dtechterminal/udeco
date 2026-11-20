// SPDX-License-Identifier: GPL-2.0-or-later

package repotest

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
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

const deployScript = `#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Deploy the thing.
#
#   deploy/thing.sh [options]
#
# Options: --host IP (default 192.168.0.9).
set -eu
DIR=/tp_data/udeco
BIN=$DIR/udeco-ap
usage() { sed -n '3,8p' "$0"; exit 2; }
guard() {
	GW=192.168.0.1
	AFTER=${GUARD_AFTER:-180} # s
	if [ -f $D/guard.conf ]; then
		NESTED=no
	fi
	log() { echo "$*"; }
}
unlock() {
	return 0
}
got=$(remote <<END || true
md5sum $BIN.new
END
)
remote <<EOF
set -e
cat >$BIN.tmp <<'LAUNCH'
#!/bin/sh
B=$BIN
want=\$(cat ${DIR}/udeco-ap.md5 2>/dev/null)
[ -x \$B ] || exit 0
echo \$\$ >$RAMDIR/agent.pid
echo 'a \\ and a \n' $(date) ${X:-y} $1
LAUNCH
chmod 755 $BIN.tmp
EOF
cat <<'JSON'
{"a": "$b"}
JSON
`

func TestShellFunc(t *testing.T) {
	if got, want := ShellFunc(t, deployScript, "unlock"), "unlock() {\n\treturn 0\n}\n"; got != want {
		t.Errorf("ShellFunc(unlock) = %q, want %q", got, want)
	}
	if got, want := ShellFunc(t, deployScript, "usage"), "usage() { sed -n '3,8p' \"$0\"; exit 2; }\n"; got != want {
		t.Errorf("ShellFunc(usage) = %q, want %q", got, want)
	}
	g := ShellFunc(t, deployScript, "guard")
	if !strings.HasPrefix(g, "guard() {\n\tGW=192.168.0.1\n") || !strings.HasSuffix(g, "\tlog() { echo \"$*\"; }\n}\n") {
		t.Errorf("ShellFunc(guard) = %q", g)
	}
	// log is defined inside guard, not in column 0
	for _, name := range []string{"log", "nosuch", "remote"} {
		if msg := reported(func(tb testing.TB) { ShellFunc(tb, deployScript, name) }); msg == "" {
			t.Errorf("ShellFunc(%s) did not fail", name)
		}
	}
}

func TestShellFuncVar(t *testing.T) {
	for name, want := range map[string]string{"GW": "192.168.0.1", "AFTER": "180"} {
		if got := ShellFuncVar(t, deployScript, "guard", name); got != want {
			t.Errorf("ShellFuncVar(guard, %s) = %q, want %q", name, got, want)
		}
	}
	// nested deeper, the script's own, not there at all
	for _, name := range []string{"NESTED", "DIR", "nosuch"} {
		if msg := reported(func(tb testing.TB) { ShellFuncVar(tb, deployScript, "guard", name) }); msg == "" {
			t.Errorf("ShellFuncVar(guard, %s) did not fail", name)
		}
	}
	if msg := reported(func(tb testing.TB) { ShellFuncVar(tb, deployScript, "nosuch", "GW") }); msg == "" {
		t.Error("ShellFuncVar did not fail for a function the script does not have")
	}
}

func TestHeader(t *testing.T) {
	want := "\nDeploy the thing.\n\n  deploy/thing.sh [options]\n\nOptions: --host IP (default 192.168.0.9).\n"
	if got := Header(deployScript, 3); got != want {
		t.Errorf("Header(3) = %q, want %q", got, want)
	}
	if got := Header(deployScript, 4); got != want[1:] {
		t.Errorf("Header(4) = %q, want %q", got, want[1:])
	}
	if got := Header(deployScript, 9); got != "" {
		t.Errorf("Header from a line that is not a comment = %q", got)
	}
	// one blank after the # goes, no more; a later comment is not the header
	if got := Header("#!/bin/sh\n#\n#x\n#  y\n# z \nset -e\n# later\n", 2); got != "\nx\n y\nz \n" {
		t.Errorf("Header = %q", got)
	}
}

func TestHeredoc(t *testing.T) {
	launch := Heredoc(t, deployScript, "LAUNCH")
	if !strings.HasPrefix(launch, "#!/bin/sh\nB=$BIN\n") || !strings.HasSuffix(launch, "${X:-y} $1") {
		t.Errorf("Heredoc(LAUNCH) = %q", launch)
	}
	if got := Heredoc(t, deployScript, "JSON"); got != `{"a": "$b"}` {
		t.Errorf("Heredoc(JSON) = %q", got)
	}
	if got := Heredoc(t, deployScript, "END"); got != "md5sum $BIN.new" {
		t.Errorf("Heredoc(END) = %q", got)
	}
	if outer := Heredoc(t, deployScript, "EOF"); !strings.HasPrefix(outer, "set -e\ncat >$BIN.tmp <<'LAUNCH'\n") || !strings.HasSuffix(outer, "\nchmod 755 $BIN.tmp") {
		t.Errorf("Heredoc(EOF) = %q", outer)
	}
	// E is a prefix of END and EOF, LAUNCHER has LAUNCH as its prefix
	for _, tag := range []string{"NOSUCH", "E", "LAUNCHER"} {
		if msg := reported(func(tb testing.TB) { Heredoc(tb, deployScript, tag) }); msg == "" {
			t.Errorf("Heredoc(%s) did not fail", tag)
		}
	}
}

func TestHeredocText(t *testing.T) {
	vars := map[string]string{"BIN": "/tp_data/udeco/udeco-ap", "DIR": "/tp_data/udeco", "RAMDIR": "/tmp/udeco-bin"}
	text, unknown := HeredocText(Heredoc(t, deployScript, "LAUNCH"), vars)
	want := "#!/bin/sh\nB=/tp_data/udeco/udeco-ap\nwant=$(cat /tp_data/udeco/udeco-ap.md5 2>/dev/null)\n" +
		"[ -x $B ] || exit 0\necho $$ >/tmp/udeco-bin/agent.pid\n" +
		"echo 'a \\ and a \\n' $(date) ${X:-y} $1"
	if text != want {
		t.Errorf("HeredocText = %q, want %q", text, want)
	}
	if text, _ := HeredocText("a \\` b \\x", vars); text != "a ` b \\x" {
		t.Errorf("HeredocText = %q", text)
	}
	// what it does not render: $(date), ${X:-y} and $1
	if !reflect.DeepEqual(unknown, []string{"$", "$", "$"}) {
		t.Errorf("unknown = %q", unknown)
	}
	if _, unknown := HeredocText("$BIN $OTHER ${THIRD}", vars); !reflect.DeepEqual(unknown, []string{"OTHER", "THIRD"}) {
		t.Errorf("unknown = %q", unknown)
	}
	text, unknown = HeredocText("${BIN}.gz $BIN.tmp cost 5$", vars)
	if text != "/tp_data/udeco/udeco-ap.gz /tp_data/udeco/udeco-ap.tmp cost 5$" || !reflect.DeepEqual(unknown, []string{"$"}) {
		t.Errorf("HeredocText = %q, %q", text, unknown)
	}
}

func TestMarkdown(t *testing.T) {
	got := Markdown(t)
	for _, want := range []string{"README.md", "docs/deco/agent-design.md", "docs/deco/features/login-lock.md"} {
		if !slices.Contains(got, want) {
			t.Errorf("Markdown() lacks %s", want)
		}
	}
	for _, p := range got {
		if !strings.HasSuffix(p, ".md") || strings.Contains(p, `\`) || strings.HasPrefix(p, ".git/") {
			t.Errorf("Markdown() lists %q", p)
		}
	}
	if !slices.IsSorted(got) {
		t.Error("Markdown() is not sorted")
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

const goSample = "internal/repotest/testdata/src.go.txt"

func TestStringConsts(t *testing.T) {
	want := map[string]string{"A": "a", "B": "b", "C": "c:d", "Lone": `raw "text"`}
	if got := StringConsts(t, goSample); !reflect.DeepEqual(got, want) {
		t.Errorf("StringConsts = %q, want %q", got, want)
	}
}

func TestSwitches(t *testing.T) {
	want := []Switch{
		{Tag: "verb", Cases: [][]string{{"dev.Unblock", "dev.GuestAuth"}}},
		{Tag: "verb", Cases: [][]string{{"dev.Reboot"}, {"dev.Scan", `"spectrum-scan"`}, {`dev.LED + ":" + dev.On`}}},
		{Tag: "", Cases: [][]string{{`arg == "x"`}}},
		{Tag: "r.Cmd", Cases: [][]string{{`"kick-sta"`, `"kick"`}}},
	}
	got := Switches(t, goSample, "act")
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Switches(act) = %+v, want %+v", got, want)
	}
	if !got[1].Has("dev.Scan") || got[1].Has("dev.Unblock") || got[1].Has("dev.LED") {
		t.Errorf("Has: %+v", got[1])
	}
	if s := SwitchOn(t, goSample, "act", "r.Cmd"); !s.Has(`"kick"`) {
		t.Errorf("SwitchOn(r.Cmd) = %+v", s)
	}
	if s := SwitchOn(t, goSample, "act", "verb"); !s.Has("dev.Unblock") {
		t.Errorf("SwitchOn(verb) is not the first one: %+v", s)
	}
	if msg := reported(func(tb testing.TB) { Switches(tb, goSample, "nosuch") }); msg == "" {
		t.Error("Switches did not fail for a function the file does not have")
	}
	if msg := reported(func(tb testing.TB) { SwitchOn(tb, goSample, "other", "verb") }); msg == "" {
		t.Error("SwitchOn did not fail for a tag the function does not switch on")
	}
}

func TestSwitchConsts(t *testing.T) {
	consts := map[string]string{"Reboot": "reboot", "Scan": "scan", "LED": "led", "On": "on"}
	values, other := SwitchOn(t, goSample, "act", "r.Cmd").Consts("dev", consts)
	if values != nil || !reflect.DeepEqual(other, []string{`"kick-sta"`, `"kick"`}) {
		t.Errorf("Consts = %q, %q", values, other)
	}
	sw := Switches(t, goSample, "act")[1]
	values, other = sw.Consts("dev", consts)
	if !reflect.DeepEqual(values, []string{"reboot", "scan"}) || !reflect.DeepEqual(other, []string{`"spectrum-scan"`, `dev.LED + ":" + dev.On`}) {
		t.Errorf("Consts = %q, %q", values, other)
	}
	if values, _ := sw.Consts("device", consts); values != nil {
		t.Errorf("Consts for another package = %q", values)
	}
}

func TestCover(t *testing.T) {
	all := []string{"a", "b", "c"}
	for _, c := range []struct {
		handled, exempt []string
		ok              bool
	}{
		{[]string{"a", "b"}, []string{"c"}, true},
		{[]string{"c", "b", "a"}, nil, true},
		{[]string{"a"}, []string{"c"}, false},           // b is in neither
		{[]string{"a", "b", "c"}, []string{"c"}, false}, // c is in both
		{[]string{"a", "b", "c"}, []string{"d"}, false}, // d is not an item
	} {
		msg := reported(func(tb testing.TB) { Cover(tb, "x", all, c.handled, c.exempt) })
		if (msg == "") != c.ok {
			t.Errorf("Cover(%q, %q) reported %q, want ok=%v", c.handled, c.exempt, msg, c.ok)
		}
	}
}
