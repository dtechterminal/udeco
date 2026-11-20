// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/stasnoop"
	"github.com/antoniocosta/unifi-openwrt/internal/wl"
)

// Tests that hold mtkwifi's small helpers to the one copy each now calls.
// The wanted answers are what each helper gave while it was its own code.

// A guest's MAC is taken in every spelling wl.NormMAC takes, trimmed, and
// kept in lower case with colons; anything else is refused in the words
// the agent logs.
func TestGuestAuthMACForms(t *testing.T) {
	f := newFakeDev(t)
	a, _ := clocked(f)
	ctx := context.Background()
	for _, c := range []struct{ in, want string }{
		{"AA:BB:CC:00:00:09", "aa:bb:cc:00:00:09"},
		{" aa:bb:cc:00:00:09\n", "aa:bb:cc:00:00:09"},
		{"AA-BB-CC-00-00-09", "aa:bb:cc:00:00:09"},
		{"aabb.cc00.0009", "aa:bb:cc:00:00:09"},
		{"01:00:5e:00:00:fb", "01:00:5e:00:00:fb"},
		{"aa:bb:cc:00:00", ""},
		{"02:00:5e:10:00:00:00:01", ""},
		{"nope", ""},
		{"", ""},
	} {
		err := a.AuthorizeGuest(ctx, c.in)
		if c.want == "" {
			if want := fmt.Sprintf("mtkwifi: guest authorisation: bad MAC %q", c.in); err == nil || err.Error() != want {
				t.Errorf("AuthorizeGuest(%q): %v, want %s", c.in, err, want)
			}
			continue
		}
		if err != nil {
			t.Errorf("AuthorizeGuest(%q): %v", c.in, err)
			continue
		}
		if got := a.loadGuestAuth(); !slices.Equal(got, []string{c.want}) {
			t.Errorf("AuthorizeGuest(%q) recorded %v, want %s", c.in, got, c.want)
		}
		if w, _ := wl.NormMAC(strings.TrimSpace(c.in)); w != c.want {
			t.Errorf("wl.NormMAC(TrimSpace(%q)) = %q, want %q", c.in, w, c.want)
		}
		if err := a.UnauthorizeGuest(ctx, c.in); err != nil || len(a.loadGuestAuth()) != 0 {
			t.Errorf("UnauthorizeGuest(%q): %v, left %v", c.in, err, a.loadGuestAuth())
		}
	}
}

// The ARP frames this package sends, byte for byte, as they were when it
// built them itself (stasnoop.ARPFrame and stasnoop.GARPFrame build them
// now). AnnounceStation checks less than stasnoop.GARP (a group address
// passes), so garp is the unchecked frame, not stasnoop.GARP.
func TestARPFramesGolden(t *testing.T) {
	hw := func(s string) net.HardwareAddr { h, _ := net.ParseMAC(s); return h }
	sta, peer := hw("aa:bb:cc:dd:ee:01"), hw("00:11:22:33:44:55")
	for _, c := range []struct {
		name  string
		frame []byte
		want  string
	}{
		{"garp", garp(sta, net.ParseIP("192.168.0.77")),
			"ffffffffffffaabbccddee0108060001080006040001aabbccddee01c0a8004d000000000000c0a8004d000000000000000000000000000000000000"},
		{"garp, a 4-byte address", garp(sta, net.ParseIP("192.168.0.77").To4()),
			"ffffffffffffaabbccddee0108060001080006040001aabbccddee01c0a8004d000000000000c0a8004d000000000000000000000000000000000000"},
		{"garp, a group address", garp(hw("01:00:5e:00:00:fb"), net.IPv4(10, 3, 0, 9)),
			"ffffffffffff01005e0000fb0806000108000604000101005e0000fb0a0300090000000000000a030009000000000000000000000000000000000000"},
		{"garp, an IPv6 address", garp(sta, net.ParseIP("fe80::1")),
			"ffffffffffffaabbccddee0108060001080006040001aabbccddee010000000000000000000000000000000000000000000000000000000000000000"},
		{"garp, nothing", garp(nil, nil),
			"ffffffffffff000000000000080600010800060400010000000000000000000000000000000000000000000000000000000000000000000000000000"},
		{"reply", arpReply(sta, net.ParseIP("192.168.0.77"), peer, net.ParseIP("192.168.0.1")),
			"001122334455aabbccddee0108060001080006040002aabbccddee01c0a8004d001122334455c0a80001000000000000000000000000000000000000"},
		{"reply to a DAD probe", arpReply(sta, net.ParseIP("192.168.0.77"), peer, net.IPv4zero),
			"001122334455aabbccddee0108060001080006040002aabbccddee01c0a8004d00112233445500000000000000000000000000000000000000000000"},
		{"reply, no target address", arpReply(sta, net.ParseIP("192.168.0.77"), peer, nil),
			"001122334455aabbccddee0108060001080006040002aabbccddee01c0a8004d00112233445500000000000000000000000000000000000000000000"},
	} {
		if got := hex.EncodeToString(c.frame); got != c.want || len(c.frame) != 60 {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// where both take the arguments, the frame is stasnoop.GARP's
	g, err := stasnoop.GARP("aa:bb:cc:dd:ee:01", "192.168.0.77")
	if err != nil || !bytes.Equal(g, garp(sta, net.ParseIP("192.168.0.77"))) {
		t.Errorf("stasnoop.GARP %x, %v", g, err)
	}
}

// netStats reads the counters apstate.VAPNetdevFields names (the list
// internal/wl reads too), each as a signed number: a counter above the
// int64 range reads as its maximum here (wl wraps it), so the number
// parsing stays this package's own.
func TestNetStatsNamesAndNumbers(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "sys/class/net/rai0/statistics")
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
	got := NewCollector(CollectorOptions{Root: root}).netStats("rai0")
	want := map[string]int64{"rx_bytes": 48216226929, "tx_bytes": math.MaxInt64, "rx_packets": -5, "tx_packets": 0,
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

// bridgeOf is bcmwifi.BridgeOf for the applier's root.
func TestBridgeOfIsBcmwifis(t *testing.T) {
	f := newFakeDev(t)
	a, _ := clocked(f)
	link := func(port, target string) {
		t.Helper()
		dir := filepath.Join(f.root, "sys/class/net", port, "brport")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(dir, "bridge")); err != nil {
			t.Fatal(err)
		}
	}
	link("rai3", "../../../devices/virtual/net/br-v20")
	link("eth0.9.1", "/sys/devices/virtual/net/br-v9/")
	for port, want := range map[string]string{"eth0.4.1": "bdg2", "ra0": "bdg2", "rai3": "br-v20", "eth0.9.1": "br-v9", "rai0": "", "nosuch": ""} {
		if got := a.bridgeOf(port); got != want {
			t.Errorf("bridgeOf(%s) = %q, want %q", port, got, want)
		}
		if got := bcmwifi.BridgeOf(f.root, port); got != want {
			t.Errorf("bcmwifi.BridgeOf(%s) = %q, want %q", port, got, want)
		}
	}
}

// writeFile replaces a file through "<name>.udeco" beside it, the name it
// has always used on the unit's flash, with the mode asked for, and leaves
// no temporary file.
func TestWriteFileTempName(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "RT2860AP.dat")
	if err := os.WriteFile(p, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(p, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "new" || fi.Mode().Perm() != 0o600 {
		t.Errorf("wrote %q mode %v", b, fi.Mode().Perm())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("left %d files", len(ents))
	}
	// the temporary name: a directory in its place makes the write fail
	if err := os.Mkdir(p+".udeco", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p+".udeco", "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(p, []byte("newer"), 0o600); err == nil {
		t.Error("wrote although <name>.udeco is taken: the temporary name changed")
	}
	if b, _ := os.ReadFile(p); string(b) != "new" {
		t.Errorf("a failed write left %q", b)
	}
}
