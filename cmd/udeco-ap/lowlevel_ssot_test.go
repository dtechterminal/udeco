// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mdnsbr"
	"github.com/dtechterminal/udeco/internal/wl"
)

// Tests that hold the agent's small helpers to the one copy each now calls
// (internal/apstate for /proc/uptime, internal/bcmwifi for a port's
// bridge, internal/atomicfile for its state files). The wanted answers are
// what each helper gave while it was its own code.

// readUptime is apstate.ParseUptime of <root>/proc/uptime, errors and all:
// the boot gate and the crash-loop guard print them.
func TestReadUptimeIsApstates(t *testing.T) {
	root := t.TempDir()
	if _, err := readUptime(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("no /proc/uptime: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, "proc"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		text string
		want float64
		err  string
	}{
		{text: "18381.41 70236.05\n", want: 18381.41},
		{text: "90.00 100.00\n", want: 90},
		{text: "8207676.06 23118573.87", want: 8207676.06},
		{text: "", err: "empty /proc/uptime"},
		{text: "\n", err: "empty /proc/uptime"},
		{text: "junk 1\n", err: `strconv.ParseFloat: parsing "junk": invalid syntax`},
	} {
		if err := os.WriteFile(filepath.Join(root, "proc/uptime"), []byte(c.text), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := readUptime(root)
		msg := ""
		if err != nil {
			msg = err.Error()
		}
		if got != c.want || msg != c.err {
			t.Errorf("readUptime(%q) = %v, %q; want %v, %q", c.text, got, msg, c.want, c.err)
		}
		if w, werr := apstate.ParseUptime(c.text); w != got || (werr == nil) != (err == nil) {
			t.Errorf("apstate.ParseUptime(%q) = %v, %v; readUptime %v, %v", c.text, w, werr, got, err)
		}
	}
}

// bridgeName is bcmwifi.BridgeOf for the agent's root.
func TestBridgeNameIsBcmwifis(t *testing.T) {
	root := t.TempDir()
	link := func(port, target string) {
		t.Helper()
		dir := filepath.Join(root, "sys/class/net", port, "brport")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "bridge")); err != nil {
			t.Fatal(err)
		}
	}
	link("wl12", "../../../devices/virtual/net/br-lan")
	link("wl13", "../../br-v20")
	link("eth0.4.1", "/sys/devices/virtual/net/bdg2/")
	if err := os.MkdirAll(filepath.Join(root, "sys/class/net/wl11"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &agent{o: options{root: root}}
	for vif, want := range map[string]string{"wl12": "br-lan", "wl13": "br-v20", "eth0.4.1": "bdg2", "wl11": "", "nosuch": ""} {
		if got := a.bridgeName(vif); got != want {
			t.Errorf("bridgeName(%s) = %q, want %q", vif, got, want)
		}
		if got := bcmwifi.BridgeOf(root, vif); got != want {
			t.Errorf("bcmwifi.BridgeOf(%s) = %q, want %q", vif, got, want)
		}
	}
}

// refuseAll is a runner whose every command fails.
type refuseAll struct{}

func (refuseAll) Run(context.Context, string, ...string) ([]byte, error) {
	return nil, errors.New("refused")
}

// The two interface-name rules, side by side. apstate.IfNameChars is the
// character rule of internal/wl, internal/bcmwifi and upstream's openwrt package;
// internal/mdnsbr, which does not import apstate, has its own and wants a
// letter or a digit first. Every name of the supported units passes both,
// and they part only on a first character of '-', '.' or '_'.
func TestInterfaceNameRules(t *testing.T) {
	mdns := func(name string) bool {
		err := (&mdnsbr.Interceptor{Run: refuseAll{}}).Set(context.Background(), []string{name})
		return err == nil || !strings.Contains(err.Error(), "is not an interface name")
	}
	alnum := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' }
	for _, c := range []struct {
		name  string
		chars bool // apstate.IfNameChars
	}{
		{"wl0", true}, {"wl1.2", true}, {"eth0.4.1", true}, {"br-lan", true}, {"ra0", true}, {"rai0", true},
		{"apcli0", true}, {"phy0-ap0", true}, {"bdg2", true}, {"ifb1", true}, {"a", true}, {"0", true},
		{"abcdefghijklmno", true}, {"abcdefghijklmnop", false},
		{"-x", true}, {".x", true}, {"_x", true}, {"-", true},
		{"", false}, {"wl0 ", false}, {"wl0\n", false}, {"wl/0", false}, {"wl0;id", false}, {"wl$0", false}, {"wl\u00e90", false},
	} {
		if got := apstate.IfNameChars(c.name); got != c.chars {
			t.Errorf("apstate.IfNameChars(%q) = %t, want %t", c.name, got, c.chars)
		}
		if got, want := mdns(c.name), c.chars && alnum(c.name[0]); got != want {
			t.Errorf("mdnsbr takes %q: %t, want %t (the same characters, a letter or a digit first)", c.name, got, want)
		}
	}
}

// takeName puts a directory with a file in it at p, so that nothing can be
// written or renamed there.
func takeName(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(p, "in-use"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// The agent's state files are replaced through "<file>.tmp" beside them
// (atomicfile.Write; the name each site has always used on the unit's
// flash and RAM disk), in the mode each had, with the directory made
// first. For each: one write leaves the file and nothing else; with the
// temporary name unusable the file stays as it was (so the name did not
// change) and what the site logged before, it logs.
func TestStateFilesThroughTmp(t *testing.T) {
	type site struct {
		name  string
		path  func(a *agent) string
		mode  os.FileMode
		write func(a *agent, n int)
		logs  string // what a failed write logs ("" = nothing)
	}
	sites := []site{
		{name: "alive record", path: func(a *agent) string { return a.alivePath() }, mode: 0o600,
			write: func(a *agent, n int) { a.markAlive(fmt.Sprintf("state-%d", n), false, "") }, logs: "alive record "},
		{name: "event log", path: func(a *agent) string { return a.events.path }, mode: 0o600,
			write: func(a *agent, n int) { a.events.add(fmt.Sprintf("event %d", n)) }, logs: "event log "},
		{name: "loop guard", path: func(a *agent) string { return a.loopFilePath() }, mode: 0o600,
			write: func(a *agent, n int) { a.recordLoopGuard(fmt.Sprintf("eth%d", n), "fdb", false) }, logs: "loop guard: recording "},
		{name: "inform counters", path: func(a *agent) string { return a.counterPath() }, mode: 0o600,
			write: func(a *agent, n int) {
				a.ctr.Begin(int64(100 + n))
				a.ctr.Netdev("if:eth0", "eth0", map[string]int64{"rx_bytes": int64(1000 * (n + 1))})
				a.saveCounters(time.Now(), true)
			}, logs: "inform counters: saving "},
		{name: "spectrum tables", path: func(a *agent) string { return a.spectrumPath() }, mode: 0o600,
			write: func(a *agent, n int) {
				a.scans.saved["ng"] = &savedTable{Radio: "wl0", Time: time.Unix(int64(1700000000+n), 0).UTC(),
					Rows: map[int][]wl.SpectrumRow{20: {{Channel: 1 + n}}}}
				a.saveSpectrum()
			}, logs: "spectrum: saving the tables to "},
	}
	for _, s := range sites {
		t.Run(s.name, func(t *testing.T) {
			root := t.TempDir()
			var logged []string
			logf := func(f string, v ...any) { logged = append(logged, fmt.Sprintf(f, v...)) }
			a := &agent{cfg: &Config{Model: "UAL6"}, o: options{root: root, base: "/flash2/udeco", runDir: "/tmp/udeco", logf: logf},
				topo: newTopology(), scans: &scanner{saved: map[string]*savedTable{}}}
			a.events = &eventLog{path: filepath.Join(root, "flash2/udeco", eventsFile), root: root, clock: time.Now, logf: logf}
			a.loadCounters()
			p := s.path(a)
			s.write(a, 0)
			first, err := os.ReadFile(p)
			if err != nil || len(first) == 0 {
				t.Fatalf("not written: %v (%q)", err, logged)
			}
			if fi, _ := os.Stat(p); fi.Mode().Perm() != s.mode {
				t.Errorf("mode %v, want %v", fi.Mode().Perm(), s.mode)
			}
			if fi, _ := os.Stat(filepath.Dir(p)); fi.Mode().Perm() != 0o700 {
				t.Errorf("directory mode %v, want 0700", fi.Mode().Perm())
			}
			if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
				t.Errorf("%d entries beside the file", len(ents)-1)
			}
			logged = nil
			takeName(t, p+".tmp")
			s.write(a, 1)
			if b, _ := os.ReadFile(p); string(b) != string(first) {
				t.Errorf("written although %s.tmp is taken: the temporary name changed", filepath.Base(p))
			}
			if s.logs != "" && (len(logged) == 0 || !strings.Contains(strings.Join(logged, "\n"), s.logs)) {
				t.Errorf("a failed write logged %q, want a line with %q", logged, s.logs)
			}
			// the write works again once the name is free, and leaves nothing
			if err := os.RemoveAll(p + ".tmp"); err != nil {
				t.Fatal(err)
			}
			s.write(a, 2)
			if b, _ := os.ReadFile(p); string(b) == string(first) {
				t.Error("not written after the temporary name was freed")
			}
			if ents, _ := os.ReadDir(filepath.Dir(p)); len(ents) != 1 {
				t.Errorf("%d entries beside the file after a failed and a good write", len(ents)-1)
			}
		})
	}
}

// The PID file beside the lock is written the same way (0644, for the
// scripts), through "udeco-ap.pid.tmp".
func TestPIDFileThroughTmp(t *testing.T) {
	dir := t.TempDir()
	l, err := acquireLock(dir)
	if err != nil {
		t.Fatal(err)
	}
	pid := filepath.Join(dir, "udeco-ap.pid")
	if b, _ := os.ReadFile(pid); strings.TrimSpace(string(b)) != fmt.Sprint(os.Getpid()) {
		t.Errorf("pid file %q", b)
	}
	if fi, _ := os.Stat(pid); fi.Mode().Perm() != 0o644 {
		t.Errorf("pid file mode %v", fi.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 { // the lock and the PID file
		t.Errorf("%d files in the run directory", len(ents))
	}
	l.release()
	if err := os.WriteFile(pid, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	takeName(t, pid+".tmp")
	if l, err = acquireLock(dir); err != nil {
		t.Fatalf("the lock must not depend on the PID file: %v", err)
	}
	defer l.release()
	if b, _ := os.ReadFile(pid); string(b) != "stale\n" {
		t.Errorf("written although udeco-ap.pid.tmp is taken: the temporary name changed: %q", b)
	}
}
