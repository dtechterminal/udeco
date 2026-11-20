// SPDX-License-Identifier: GPL-2.0-or-later

package stasnoop

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
)

// GARP's frames, byte for byte, as they were when GARP wrote the frame
// out itself (it now checks its two arguments and calls GARPFrame), and
// what it refuses.
func TestGARPGolden(t *testing.T) {
	for _, c := range []struct{ mac, ip, hex, err string }{
		{mac: "AA:BB:CC:DD:EE:01", ip: "192.168.0.77",
			hex: "ffffffffffffaabbccddee0108060001080006040001aabbccddee01c0a8004d000000000000c0a8004d000000000000000000000000000000000000"},
		{mac: "aa-bb-cc-dd-ee-01", ip: "::ffff:10.3.0.9",
			hex: "ffffffffffffaabbccddee0108060001080006040001aabbccddee010a0300090000000000000a030009000000000000000000000000000000000000"},
		{mac: "01:00:5e:00:00:fb", ip: "10.3.0.9", err: "stasnoop: GARP: not a unicast MAC"},
		{mac: "02:00:5e:10:00:00:00:01", ip: "10.0.0.1", err: "stasnoop: GARP: not a unicast MAC"},
		{mac: "zz", ip: "10.0.0.1", err: "stasnoop: GARP: not a unicast MAC"},
		{mac: "aa:bb:cc:dd:ee:01", ip: "fe80::1", err: "stasnoop: GARP: not an IPv4 address"},
		{mac: "aa:bb:cc:dd:ee:01", ip: "0.0.0.0", err: "stasnoop: GARP: not an IPv4 address"},
		{mac: "aa:bb:cc:dd:ee:01", ip: "", err: "stasnoop: GARP: not an IPv4 address"},
	} {
		f, err := GARP(c.mac, c.ip)
		got := ""
		if err != nil {
			got = err.Error()
		}
		if hex.EncodeToString(f) != c.hex || got != c.err {
			t.Errorf("GARP(%q, %q) = %x, %q; want %s, %q", c.mac, c.ip, f, got, c.hex, c.err)
		}
	}
}

// ARPFrame's and GARPFrame's bytes, as internal/mtkwifi's own builders
// gave them before they moved here (mtkwifi's tests hold its callers to
// the same frames). Nothing is checked: an address of another size is
// copied or left zero as it comes.
func TestARPFrameGolden(t *testing.T) {
	hw := func(s string) net.HardwareAddr { h, _ := net.ParseMAC(s); return h }
	for _, c := range []struct {
		name  string
		frame []byte
		want  string
	}{
		{"any operation", ARPFrame(hw("00:11:22:33:44:55"), hw("aa:bb:cc:dd:ee:01"), 0x1234, net.IPv4(1, 2, 3, 4), hw("66:77:88:99:aa:bb"), net.IPv4(5, 6, 7, 8)),
			"001122334455aabbccddee0108060001080006041234aabbccddee010102030466778899aabb05060708000000000000000000000000000000000000"},
		{"a reply", ARPFrame(hw("00:11:22:33:44:55"), hw("aa:bb:cc:dd:ee:01"), 2, net.ParseIP("192.168.0.77"), hw("00:11:22:33:44:55"), net.ParseIP("192.168.0.1")),
			"001122334455aabbccddee0108060001080006040002aabbccddee01c0a8004d001122334455c0a80001000000000000000000000000000000000000"},
		{"garp", GARPFrame(hw("aa:bb:cc:dd:ee:01"), net.ParseIP("192.168.0.77")),
			"ffffffffffffaabbccddee0108060001080006040001aabbccddee01c0a8004d000000000000c0a8004d000000000000000000000000000000000000"},
		{"garp, a group address", GARPFrame(hw("01:00:5e:00:00:fb"), net.IPv4(10, 3, 0, 9)),
			"ffffffffffff01005e0000fb0806000108000604000101005e0000fb0a0300090000000000000a030009000000000000000000000000000000000000"},
		{"garp, an IPv6 address", GARPFrame(hw("aa:bb:cc:dd:ee:01"), net.ParseIP("fe80::1")),
			"ffffffffffffaabbccddee0108060001080006040001aabbccddee010000000000000000000000000000000000000000000000000000000000000000"},
		{"garp, an 8-byte address", GARPFrame(hw("02:00:5e:10:00:00:00:01"), net.IPv4(10, 3, 0, 9)),
			"ffffffffffff02005e1000000806000108000604000102005e1000000a0300090000000000000a030009000000000000000000000000000000000000"},
		{"garp, nothing", GARPFrame(nil, nil),
			"ffffffffffff000000000000080600010800060400010000000000000000000000000000000000000000000000000000000000000000000000000000"},
	} {
		if got := hex.EncodeToString(c.frame); got != c.want || len(c.frame) != 60 {
			t.Errorf("%s: %s, want %s", c.name, got, c.want)
		}
	}
	// GARP is GARPFrame of what it parsed
	g, err := GARP("AA:BB:CC:DD:EE:01", "192.168.0.77")
	if err != nil || !bytes.Equal(g, GARPFrame(hw("aa:bb:cc:dd:ee:01"), net.IPv4(192, 168, 0, 77))) {
		t.Errorf("GARP %x, %v", g, err)
	}
}
