// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
)

// macForms is what the MAC normaliser of this package gives for each
// spelling ("" = refused). internal/bcmwifi and internal/mtkwifi hold
// their callers to the same table (with the surrounding space they trim).
var macForms = []struct{ in, want string }{
	{"8C:BF:EA:1D:BA:74", "8c:bf:ea:1d:ba:74"},
	{"8c:bf:ea:1d:ba:74", "8c:bf:ea:1d:ba:74"},
	{"8C-BF-EA-1D-BA-74", "8c:bf:ea:1d:ba:74"},
	{"8cbf.ea1d.ba74", "8c:bf:ea:1d:ba:74"},
	{"01:00:5e:00:00:fb", "01:00:5e:00:00:fb"}, // a group address is a MAC here (ftpeer.NormMAC refuses it)
	{"00:00:00:00:00:00", "00:00:00:00:00:00"},
	{"ff:ff:ff:ff:ff:ff", "ff:ff:ff:ff:ff:ff"},
	{" 8c:bf:ea:1d:ba:74", ""}, // no trimming here: the callers that take user text trim first
	{"8c:bf:ea:1d:ba:74\n", ""},
	{"8c:bf:ea:1d:ba", ""},
	{"8c:bf:ea:1d:ba:74:00", ""},
	{"02:00:5e:10:00:00:00:01", ""}, // EUI-64: net.ParseMAC takes it, a station is 6 bytes
	{"8c:bf:ea:1d:ba:7g", ""},
	{"zz", ""},
	{"", ""},
}

func TestNormMAC(t *testing.T) {
	for _, c := range macForms {
		got, err := NormMAC(c.in)
		if got != c.want || (err == nil) != (c.want != "") {
			t.Errorf("NormMAC(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
		if err != nil && err.Error() != fmt.Sprintf("bad MAC %q", c.in) {
			t.Errorf("NormMAC(%q): error %q", c.in, err)
		}
	}
}

// assoclistSamples are `wl assoclist` texts: the captures of the unit
// (testdata) and the forms the tests of this package and of bcmwifi feed.
func assoclistSamples(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{
		"spectrum test":   wl02Clients,
		"one":             "assoclist 00:11:22:33:44:55\n",
		"no final \\n":    "assoclist AA:BB:CC:00:00:01\nassoclist AA:BB:CC:00:00:02",
		"empty":           "",
		"junk and a bare": "assoclist 8C:BF:EA:1D:BA:74\nassoclist zz\nassoclist\n",
	}
	files, err := filepath.Glob("testdata/*assoclist*.txt")
	if err != nil || len(files) == 0 {
		t.Fatalf("no assoclist captures in testdata: %v", err)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		m[f] = string(b)
	}
	return m
}

// exactlyTwo is the rule this package had for an assoclist line before
// ParseAssoclist became the one parser: "assoclist" and a MAC and nothing
// else. bcmwifi took a line with more fields too.
func exactlyTwo(out string) []string {
	var macs []string
	for line := range strings.Lines(out) {
		f := strings.Fields(line)
		if len(f) == 2 && f[0] == "assoclist" {
			if mac, err := NormMAC(f[1]); err == nil {
				macs = append(macs, mac)
			}
		}
	}
	return macs
}

// The two rules for an assoclist line (exactly two fields here, two or
// more in bcmwifi) give the same list for every capture and sample: the
// driver prints "assoclist <MAC>" and nothing after it. That is what lets
// ParseAssoclist be one parser with one rule (two or more).
func TestParseAssoclistRules(t *testing.T) {
	lines := 0
	for name, text := range assoclistSamples(t) {
		got, old := ParseAssoclist(text), exactlyTwo(text)
		if !slices.Equal(got, old) {
			t.Errorf("%s: ParseAssoclist %v, the exactly-two rule %v", name, got, old)
		}
		for _, m := range got {
			if m != strings.ToLower(m) || len(m) != 17 {
				t.Errorf("%s: %q is not a lower-case MAC", name, m)
			}
		}
		lines += len(got)
	}
	if lines < 9 {
		t.Errorf("only %d stations in all the samples: the captures are not being read", lines)
	}
	// the driver's order is kept (bcmwifi sorts for itself)
	if got := ParseAssoclist("assoclist 00:00:00:00:00:02\nassoclist 00:00:00:00:00:01\n"); !slices.Equal(got, []string{"00:00:00:00:00:02", "00:00:00:00:00:01"}) {
		t.Errorf("order: %v", got)
	}
	// where the two rules part: a line with something after the MAC
	if got := ParseAssoclist("assoclist 8C:BF:EA:1D:BA:74 -55\n"); !slices.Equal(got, []string{"8c:bf:ea:1d:ba:74"}) {
		t.Errorf("a line with a third field: %v", got)
	}
}

// parseProcStat is apstate.ParseCPULine on the first line of /proc/stat.
// The answers are what it gave while the sum was written here.
func TestParseProcStatFirstLine(t *testing.T) {
	for _, c := range []struct {
		in          string
		total, idle int64
	}{
		{string(fixture(t, "proc_stat.txt")), 146532 + 174312 + 7024149 + 65 + 8086, 7024149 + 65},
		{"cpu 1 2 3 4 5 6 7\n", 28, 9},
		{"cpu 1 2 3 4\n", 10, 4}, // "cpu" and four numbers: the least taken
		{"cpu 1 2 3\n", 0, 0},
		{"cpu0 1 2 3 4 5\n", 0, 0},
		{"intr 1 2 3\ncpu 1 2 3 4 5\n", 0, 0},      // the first line only
		{"cpu 1 2 3 4 5\ncpu0 9 9 9 9 9\n", 15, 9}, // the lines after it are not summed
		{"cpu 1 x 3 4 5\n", 13, 9},                 // an unreadable number counts 0
		{"cpu 1 2 3 4 5", 15, 9},
		{"", 0, 0},
	} {
		if total, idle := parseProcStat(c.in); total != c.total || idle != c.idle {
			t.Errorf("parseProcStat(%q) = %d, %d; want %d, %d", c.in, total, idle, c.total, c.idle)
		}
	}
}

// readSystem's uptime is apstate.ParseUptime in whole seconds; a file it
// cannot read a number from gives 0 and no error, and an empty one leaves
// what the Snapshot had, as before.
func TestReadSystemUptime(t *testing.T) {
	root := buildRoot(t)
	c := New(Options{Root: root, Run: &fakeRunner{}})
	for text, want := range map[string]int64{"": 77, " \n": 77, "junk 1\n": 0, "12.9 1\n": 12} {
		if err := os.WriteFile(filepath.Join(root, "proc/uptime"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		s := &apstate.Snapshot{Uptime: 77}
		if err := c.readSystem(s); err != nil || s.Uptime != want {
			t.Errorf("uptime %q over a Snapshot that had 77: %d, %v; want %d", text, s.Uptime, err, want)
		}
	}
	for text, want := range map[string]int64{
		string(fixture(t, "proc_uptime.txt")): 18381,
		"90.00 100.00\n":                      90,
		"8207676.06 23118573.87":              8207676,
		"0.99 1\n":                            0,
		"junk 1\n":                            0,
		"\n":                                  0,
		"":                                    0,
	} {
		if err := os.WriteFile(filepath.Join(root, "proc/uptime"), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
		s := &apstate.Snapshot{}
		if err := c.readSystem(s); err != nil || s.Uptime != want {
			t.Errorf("uptime %q: %d, %v; want %d", text, s.Uptime, err, want)
		}
	}
}

// netStats reads the files apstate.VAPNetdevFields names, each as an
// unsigned 64-bit counter (a kernel counter above the int64 range wraps,
// anything else unreadable is 0). internal/mtkwifi reads the same names
// as signed numbers, so only the names are shared.
func TestNetStatsNamesAndNumbers(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sys/class/net/wl02/statistics")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]string{
		"rx_bytes": "48216226929\n", "tx_bytes": "18446744073709551615\n", "rx_packets": "-5\n", "tx_packets": "junk\n",
		"rx_errors": "", "tx_errors": " 7 \n", "collisions": "9\n", "multicast": "3\n", // rx_dropped, tx_dropped: no file
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got := New(Options{Root: root, Run: &fakeRunner{}}).netStats("wl02")
	want := map[string]int64{"rx_bytes": 48216226929, "tx_bytes": -1, "rx_packets": 0, "tx_packets": 0,
		"rx_errors": 0, "tx_errors": 7, "rx_dropped": 0, "tx_dropped": 0}
	if len(got) != len(want) {
		t.Errorf("netStats has %d counters %v, want %d", len(got), got, len(want))
	}
	for k, w := range want {
		if v, ok := got[k]; !ok || v != w {
			t.Errorf("netStats[%s] = %d (%t), want %d", k, v, ok, w)
		}
	}
	if len(got) != len(apstate.VAPNetdevFields) {
		t.Errorf("netStats has %d counters, apstate.VAPNetdevFields %d", len(got), len(apstate.VAPNetdevFields))
	}
	for _, k := range apstate.VAPNetdevFields {
		if _, ok := got[k]; !ok {
			t.Errorf("netStats does not read %s, which apstate.VAPNetdevFields names", k)
		}
	}
}

// ifaceOK is apstate.IfNameChars and no leading '-': the name follows
// `wl -i`, where a '-' would be read as an option. The answers are what it
// gave while the character loop was written here.
func TestIfaceOKIsApstatesAndNoDash(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"wl0", true}, {"wl1.2", true}, {"eth0.4.1", true}, {"br-lan", true}, {"ra0", true}, {"rai0", true},
		{"apcli0", true}, {"phy0-ap0", true}, {"wds0.1.1", true}, {"a", true},
		{".x", true}, {"_x", true},
		{"-x", false}, {"-", false}, {"-i", false},
		{"abcdefghijklmno", true},   // 15
		{"abcdefghijklmnop", false}, // 16
		{"", false}, {"wl0 ", false}, {"wl0\n", false}, {"wl/0", false}, {"wl0;id", false}, {"wl$0", false},
		{"wl\x000", false}, {"wlé0", false}, {"wl\xff0", false}, {"wl:0", false},
	} {
		if got := ifaceOK(c.in); got != c.want {
			t.Errorf("ifaceOK(%q) = %v, want %v", c.in, got, c.want)
		}
		if got := apstate.IfNameChars(c.in) && c.in[0] != '-'; got != c.want {
			t.Errorf("apstate.IfNameChars(%q) and no leading '-' = %v, want %v", c.in, got, c.want)
		}
	}
}
