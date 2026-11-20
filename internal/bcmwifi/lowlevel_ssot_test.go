// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/wl"
)

// Tests that hold bcmwifi's small helpers to the one copy each now calls
// (internal/wl for MAC text and the association list, internal/apstate
// for interface names). The wanted answers are what each helper gave
// while it was its own code.

// normMAC is wl.NormMAC after trimming the space a config or a command
// line may carry.
func TestNormMACIsWLs(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"8C:BF:EA:1D:BA:74", "8c:bf:ea:1d:ba:74"},
		{"8c:bf:ea:1d:ba:74", "8c:bf:ea:1d:ba:74"},
		{" 8c:bf:ea:1d:ba:74\n", "8c:bf:ea:1d:ba:74"},
		{"\t8C-BF-EA-1D-BA-74 ", "8c:bf:ea:1d:ba:74"},
		{"8cbf.ea1d.ba74", "8c:bf:ea:1d:ba:74"},
		{"01:00:5e:00:00:fb", "01:00:5e:00:00:fb"},
		{"00:00:00:00:00:00", "00:00:00:00:00:00"},
		{"8c:bf:ea:1d:ba", ""},
		{"8c:bf:ea:1d:ba:74:00", ""},
		{"02:00:5e:10:00:00:00:01", ""},
		{"8c:bf:ea:36: cb:74", ""},
		{"nope", ""},
		{"", ""},
		{"  ", ""},
	} {
		if got := normMAC(c.in); got != c.want {
			t.Errorf("normMAC(%q) = %q, want %q", c.in, got, c.want)
		}
		if w, _ := wl.NormMAC(strings.TrimSpace(c.in)); w != c.want {
			t.Errorf("wl.NormMAC(TrimSpace(%q)) = %q, want %q", c.in, w, c.want)
		}
	}
}

// parseAssoclist is wl.ParseAssoclist, sorted: the trees are compared as
// sorted lists.
func TestParseAssoclistIsWLs(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{"", nil},
		{"assoclist 8C:BF:EA:1D:BA:74\n", []string{"8c:bf:ea:1d:ba:74"}},
		{"assoclist FC:3C:D7:CA:38:BB\nassoclist 8C:BF:EA:1D:BA:74\nassoclist F4:CF:A2:1E:72:64", []string{"8c:bf:ea:1d:ba:74", "f4:cf:a2:1e:72:64", "fc:3c:d7:ca:38:bb"}},
		{"assoclist 8C:BF:EA:1D:BA:74\nassoclist zz\nassoclist\nwl: not found\n", []string{"8c:bf:ea:1d:ba:74"}},
		{"  assoclist\t8C:BF:EA:1D:BA:74  \r\n", []string{"8c:bf:ea:1d:ba:74"}},
		{"assoclist 8C:BF:EA:1D:BA:74 -55\n", []string{"8c:bf:ea:1d:ba:74"}}, // two or more fields
		{"Assoclist 8C:BF:EA:1D:BA:74\n", nil},
	} {
		got := parseAssoclist(c.in)
		if !slices.Equal(got, c.want) {
			t.Errorf("parseAssoclist(%q) = %v, want %v", c.in, got, c.want)
		}
		w := wl.ParseAssoclist(c.in)
		slices.Sort(w)
		if !slices.Equal(got, w) {
			t.Errorf("parseAssoclist(%q) = %v, wl.ParseAssoclist sorted %v", c.in, got, w)
		}
	}
}

// ifnameOK is apstate.IfNameChars: a name that starts with '-', '.' or
// '_' passes here (the name goes to argv after a fixed option, never
// first), which internal/wl refuses for its own commands.
func TestIfnameOKIsApstates(t *testing.T) {
	for _, c := range []struct {
		in   string
		want bool
	}{
		{"wl0", true}, {"wl1.2", true}, {"eth0.4.1", true}, {"br-lan", true}, {"ra0", true}, {"rai0", true},
		{"apcli0", true}, {"phy0-ap0", true}, {"ifb1", true}, {"wds0.1.1", true},
		{"-x", true}, {".x", true}, {"_x", true}, {"a", true},
		{"abcdefghijklmno", true},   // 15
		{"abcdefghijklmnop", false}, // 16
		{"", false}, {"wl0 ", false}, {"wl0\n", false}, {"wl/0", false}, {"wl0;id", false}, {"wl$0", false},
		{"wl\x000", false}, {"wlé0", false}, {"wl:0", false},
	} {
		if got := ifnameOK(c.in); got != c.want {
			t.Errorf("ifnameOK(%q) = %v, want %v", c.in, got, c.want)
		}
		if got := apstate.IfNameChars(c.in); got != c.want {
			t.Errorf("apstate.IfNameChars(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// BridgeOf reads a port's bridge from sysfs under a root; the applier's
// bridgeOf is that for its own root.
func TestBridgeOf(t *testing.T) {
	root := t.TempDir()
	mk := func(port, target string) {
		t.Helper()
		dir := filepath.Join(root, "sys/class/net", port, "brport")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "bridge")); err != nil {
			t.Fatal(err)
		}
	}
	mk("wl02", "../../../devices/virtual/net/br-lan")
	mk("eth0.4.1", "../../bdg2")
	mk("wl13", "/sys/devices/virtual/net/br-v20/")
	if err := os.MkdirAll(filepath.Join(root, "sys/class/net/wl11"), 0o755); err != nil {
		t.Fatal(err)
	}
	a := &Applier{o: Options{Root: root}}
	for port, want := range map[string]string{"wl02": "br-lan", "eth0.4.1": "bdg2", "wl13": "br-v20", "wl11": "", "nosuch": ""} {
		if got := BridgeOf(root, port); got != want {
			t.Errorf("BridgeOf(%s) = %q, want %q", port, got, want)
		}
		if got := a.bridgeOf(port); got != want {
			t.Errorf("bridgeOf(%s) = %q, want %q", port, got, want)
		}
	}
}

// saveSlots makes the run directory (0700) and replaces slots.json through
// "slots.json.tmp" (the name it has always used; atomicfile.Write now),
// mode 0600. With the temporary name unusable the memory stays as it was
// and the failure is logged.
func TestSaveSlotsThroughTmp(t *testing.T) {
	root := t.TempDir()
	var logged []string
	a := &Applier{o: Options{Root: root, RunDir: "/tmp/udeco", Logf: func(f string, v ...any) { logged = append(logged, f) }}}
	lay := func(vif, id string) *layout {
		return &layout{Radios: []*radioLayout{{Used: []vifAssign{{Vif: vif, SSID: SSID{ID: id}}}}}}
	}
	a.saveSlots(lay("wl12", "home"))
	dir := filepath.Join(root, "tmp/udeco")
	p := filepath.Join(dir, "slots.json")
	if b, _ := os.ReadFile(p); string(b) != `{"wl12":"home"}` {
		t.Fatalf("slots.json %q (%v)", b, logged)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("slots.json mode %v", fi.Mode().Perm())
	}
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 {
		t.Errorf("run directory mode %v", fi.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("%d files left", len(ents))
	}
	if err := os.MkdirAll(filepath.Join(p+".tmp", "in-use"), 0o755); err != nil {
		t.Fatal(err)
	}
	a.saveSlots(lay("wl13", "iot"))
	if b, _ := os.ReadFile(p); string(b) != `{"wl12":"home"}` {
		t.Errorf("saved although slots.json.tmp is taken: the temporary name changed: %q", b)
	}
	if len(logged) != 1 || !strings.HasPrefix(logged[0], "bcmwifi: recording vif slots: ") {
		t.Errorf("logged %q", logged)
	}
}
