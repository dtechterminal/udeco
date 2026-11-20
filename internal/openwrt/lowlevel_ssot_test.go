// SPDX-License-Identifier: GPL-2.0-or-later

package openwrt

import (
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// The script Collect runs on the AP, as it was when the per-interface
// counter names were written into it: the "=== stats" loop is now rendered
// from apstate.VAPNetdevFields (the list internal/wl and internal/mtkwifi
// read too), and what reaches the AP must not change by a byte.
func TestCollectScriptGolden(t *testing.T) {
	golden(t, "collect.sh", collectScript)
	if CollectScript() != collectScript {
		t.Error("CollectScript is not the script Collect runs")
	}
	loop := "for f in " + strings.Join(apstate.VAPNetdevFields, " ") + "; do printf '%s=%s\\n' $f $(cat /sys/class/net/$i/statistics/$f); done\n"
	if strings.Count(collectScript, loop) != 1 {
		t.Errorf("the stats loop over apstate.VAPNetdevFields is not in the script once:\n%s", loop)
	}
}

// parseTop is Parse of a collect output with only the sections the system
// fields come from.
func parseTop(t *testing.T, sections string) *Snapshot {
	t.Helper()
	s, err := Parse([]byte("=== board\n{\"hostname\":\"ap\",\"model\":\"m\"}\n"+sections), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// The "cpu" section (`head -1 /proc/stat`) is summed by
// apstate.ParseCPULine, the sum internal/wl uses. The answers are what
// Parse gave while it summed the line itself.
func TestParseCPUSection(t *testing.T) {
	for _, c := range []struct {
		in          string
		total, idle int64
	}{
		{"cpu  146532 0 174312 7024149 65 0 8086 0 0 0\n", 7353144, 7024214},
		{"cpu 1 2 3 4 5 6 7\n", 28, 9},
		{"cpu 1 2 3 4\n", 10, 4},
		{"cpu 1 2 3\n", 0, 0},
		{"cpu0 1 2 3 4 5\n", 0, 0},
		{"cpu 1 x 3 4 5\n", 13, 9},
		{"", 0, 0},
		// the section is one line on an AP; were it more, every field counted (internal/wl takes the first line only)
		{"cpu 1 2 3 4 5\ncpu0 9 9 9 9 9\n", 60, 9},
	} {
		s := parseTop(t, "=== cpu\n"+c.in)
		if s.CPUTotal != c.total || s.CPUIdle != c.idle {
			t.Errorf("cpu section %q: %d, %d; want %d, %d", c.in, s.CPUTotal, s.CPUIdle, c.total, c.idle)
		}
	}
	if s := parseTop(t, ""); s.CPUTotal != 0 || s.CPUIdle != 0 {
		t.Errorf("no cpu section: %d, %d", s.CPUTotal, s.CPUIdle)
	}
}

// The "arp" section keeps an incomplete entry (flags 0x0) that has a MAC,
// which internal/wl's parseARP skips: the two readers of /proc/net/arp
// take different rows, so they stay two (apstate/proc.go).
func TestParseARPSectionKeepsIncomplete(t *testing.T) {
	s := parseTop(t, "=== arp\nIP address       HW type     Flags       HW address            Mask     Device\n"+
		"192.168.1.1      0x1         0x2         1E:6A:1B:C5:04:C2     *        br-lan\n"+
		"192.168.1.7      0x1         0x0         b0:a7:b9:3e:16:94     *        br-lan\n"+
		"192.168.1.9      0x1         0x0         00:00:00:00:00:00     *        br-lan\n")
	if len(s.ARP) != 2 || s.ARP["1e:6a:1b:c5:04:c2"] != "192.168.1.1" || s.ARP["b0:a7:b9:3e:16:94"] != "192.168.1.7" {
		t.Errorf("arp %v", s.ARP)
	}
}

// ifnameTable is what the two interface-name validators this package had
// (ifaceSafe for the scan and the neighbour report, a pattern called
// ifnameOK for the guest rules, the shaping and the QoS map) each answered:
// the same for every name. One is left, ifnameOK, and it is
// apstate.IfNameChars.
var ifnameTable = []struct {
	in   string
	want bool
}{
	{"wl0", true}, {"wl1.2", true}, {"eth0.4.1", true}, {"br-lan", true}, {"ra0", true}, {"rai0", true},
	{"apcli0", true}, {"phy0-ap0", true}, {"phy1-ap0", true}, {"uowscan0", true}, {"a", true},
	{"-x", true}, {".x", true}, {"_x", true}, {"-", true},
	{"abcdefghijklmno", true},   // 15
	{"abcdefghijklmnop", false}, // 16
	{"", false}, {"wl0 ", false}, {"wl0\n", false}, {"wl/0", false}, {"wl0;id", false}, {"wl$0", false}, {"wl0'", false},
	{"wl\x000", false}, {"wlé0", false}, {"wl\xff0", false}, {"wl:0", false}, {"$(id)", false},
}

func TestIfnameOKIsApstates(t *testing.T) {
	for _, c := range ifnameTable {
		if got := ifnameOK(c.in); got != c.want {
			t.Errorf("ifnameOK(%q) = %v, want %v", c.in, got, c.want)
		}
		if got := apstate.IfNameChars(c.in); got != c.want {
			t.Errorf("apstate.IfNameChars(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}
