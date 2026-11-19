// SPDX-License-Identifier: GPL-2.0-or-later

package lldp

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
	"unicode/utf8"
)

// A device on the unit's free port that floods LLDPDUs with a new chassis
// ID each must not grow the table without bound; the gateway already heard
// on the uplink stays, and a flooded port takes new neighbours again once
// the flood's entries expire.
func TestHeardBoundsTablePerPort(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	s := New(Options{Now: func() time.Time { return now }})
	gw := mustDecode(t, ucgFrame(120))
	s.Heard("eth0", gw)
	for i := 0; i < 10000; i++ {
		s.Heard("eth1", Neighbor{ChassisID: fmt.Sprintf("spoof-%d", i), PortID: "p", TTL: 60})
	}
	if n := len(s.Neighbors("eth1")); n > maxPerPort {
		t.Fatalf("eth1 keeps %d neighbours after a flood (bound %d)", n, maxPerPort)
	}
	if got := s.Neighbors("eth0"); len(got) != 1 || got[0].ChassisID != gw.ChassisID {
		t.Fatalf("uplink neighbours after a flood on eth1: %+v", got)
	}
	// a known neighbour is still refreshed on a full port
	s.Heard("eth1", Neighbor{ChassisID: "spoof-0", PortID: "p", TTL: 600})
	now = now.Add(61 * time.Second)
	if got := s.Neighbors("eth1"); len(got) != 1 || got[0].ChassisID != "spoof-0" {
		t.Fatalf("eth1 after the flood expired: %+v", got)
	}
	s.Heard("eth1", gw)
	if got := s.PortsHearing(gw.ChassisID); len(got) != 2 {
		t.Errorf("PortsHearing after expiry = %v", got)
	}
}

// Decode never panics and never returns control characters in the text
// fields the inform carries, whatever the frame holds.
func FuzzDecode(f *testing.F) {
	f.Add(ucgFrame(120))
	if b, err := Encode(apMAC, apInfo()); err == nil {
		f.Add(b)
	}
	hdr := append(append(append([]byte{}, MulticastMAC...), apMAC...), 0x88, 0xcc)
	f.Add(hdr)
	f.Add(append(append([]byte{}, hdr...), 0xff, 0xff))                                    // TLV longer than the frame
	f.Add(append(append([]byte{}, hdr[:12]...), 0x81, 0x00, 0, 1, 0x88, 0xcc, 0x02, 0x01)) // tagged, short chassis
	mgmt := binary.BigEndian.AppendUint16(append([]byte{}, hdr...), tlvMgmtAddr<<9|3)
	f.Add(append(mgmt, 0xff, 1, 2)) // address length past the TLV
	f.Fuzz(func(t *testing.T, frame []byte) {
		n, err := Decode(frame)
		if err != nil {
			return
		}
		for name, v := range map[string]string{"chassis": n.ChassisID, "port": n.PortID, "port descr": n.PortDescr,
			"sysname": n.SysName, "sysdescr": n.SysDescr} {
			if !utf8.ValidString(v) {
				t.Fatalf("%s %q is not UTF-8", name, v)
			}
			for _, r := range v {
				if r < 0x20 || r == 0x7f {
					t.Fatalf("%s %q holds a control character", name, v)
				}
			}
		}
		for _, ip := range n.MgmtIPs {
			if net.ParseIP(ip) == nil {
				t.Fatalf("management address %q", ip)
			}
		}
	})
}
