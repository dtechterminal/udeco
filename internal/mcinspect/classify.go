// SPDX-License-Identifier: GPL-2.0-or-later

// Package mcinspect is the agent's multicast inspection (the controller's
// "multicast inspect", fw3_caps 0x80): it classifies the group-addressed
// frames a Wi-Fi VAP receives from and sends to its clients and renders the
// per-client sta_table[].multicast block a real UniFi AP reports
// (docs/deco/features/multicast-inspect.md).
//
// Frames come from an AF_PACKET socket per VAP (raw_linux.go); everything
// else is pure and runs in tests.
package mcinspect

import (
	"encoding/binary"
	"net/netip"
	"strings"
)

// Types are the traffic classes a real U6 Pro reports in
// sta_table[].multicast.types (docs/reference/u6pro/mca-dump.json): every
// one is always present, with zero counters when nothing was seen.
var Types = []string{"arp", "dhcp", "dhcpv6", "igmp", "ipv6_nd", "mdns", "mld", "other", "ssdp", "stream", "ubnt"}

// Frame is what one group-addressed frame is, for accounting.
type Frame struct {
	Src     string     // source MAC, lower case aa:bb:cc:dd:ee:ff
	Type    string     // one of Types
	Group   netip.Addr // destination address (unspecified 0.0.0.0 for ARP and non-IP)
	Port    int        // UDP destination port, 0 otherwise
	Len     int        // frame length in bytes, as received
	Join    []netip.Addr
	Leave   []netip.Addr
	MDNS    *MDNS // the parsed mDNS message (UDP 5353), nil otherwise
	IsGroup bool  // the destination MAC is a group (multicast/broadcast) address
	// SrcGroup: the source MAC has the group bit set (never a station)
	SrcGroup bool
}

var zero4 = netip.AddrFrom4([4]byte{})

// Classify parses an Ethernet frame (b may be shorter than length when it
// was truncated; length is the frame's real size). ok is false for frames
// too short to carry an Ethernet header.
func Classify(b []byte, length int) (Frame, bool) {
	if len(b) < 14 {
		return Frame{}, false
	}
	f := Frame{Src: mac(b[6:12]), Type: "other", Group: zero4, Len: length, IsGroup: b[0]&1 == 1, SrcGroup: b[6]&1 == 1}
	et := binary.BigEndian.Uint16(b[12:14])
	p := b[14:]
	if et == 0x8100 || et == 0x88a8 { // one VLAN tag
		if len(p) < 4 {
			return f, true
		}
		et, p = binary.BigEndian.Uint16(p[2:4]), p[4:]
	}
	switch et {
	case 0x0806:
		f.Type = "arp"
	case 0x0800:
		ipv4(&f, p)
	case 0x86dd:
		ipv6(&f, p)
	}
	return f, true
}

func ipv4(f *Frame, p []byte) {
	if len(p) < 20 || p[0]>>4 != 4 {
		return
	}
	ihl := int(p[0]&0x0f) * 4
	if ihl < 20 || len(p) < ihl {
		return
	}
	dst := netip.AddrFrom4([4]byte(p[16:20]))
	f.Group = dst
	proto := p[9]
	frag := binary.BigEndian.Uint16(p[6:8])&0x1fff != 0
	l4 := p[ihl:]
	switch {
	case proto == 2 && !frag:
		f.Type = "igmp"
		igmp(f, l4)
	case proto == 17 && !frag && len(l4) >= 8:
		sport, dport := int(binary.BigEndian.Uint16(l4[0:2])), int(binary.BigEndian.Uint16(l4[2:4]))
		f.Port = dport
		f.Type = udpType(sport, dport, dst.IsMulticast(), false)
		if f.Type == "mdns" {
			f.MDNS = ParseMDNS(l4[8:])
		}
	case dst.IsMulticast():
		f.Type = "stream"
	}
}

func ipv6(f *Frame, p []byte) {
	if len(p) < 40 || p[0]>>4 != 6 {
		return
	}
	dst := netip.AddrFrom16([16]byte(p[24:40]))
	f.Group = dst
	next, l4 := p[6], p[40:]
	// hop-by-hop (MLD carries a router alert), routing, destination options
	for i := 0; i < 4 && (next == 0 || next == 43 || next == 60); i++ {
		if len(l4) < 8 {
			return
		}
		n := (int(l4[1]) + 1) * 8
		if len(l4) < n {
			return
		}
		next, l4 = l4[0], l4[n:]
	}
	switch {
	case next == 58 && len(l4) >= 4:
		switch t := l4[0]; {
		case t == 130 || t == 131 || t == 132 || t == 143:
			f.Type = "mld"
			mld(f, l4)
		case t >= 133 && t <= 137:
			f.Type = "ipv6_nd"
		case dst.IsMulticast():
			f.Type = "stream"
		}
	case next == 17 && len(l4) >= 8:
		sport, dport := int(binary.BigEndian.Uint16(l4[0:2])), int(binary.BigEndian.Uint16(l4[2:4]))
		f.Port = dport
		f.Type = udpType(sport, dport, dst.IsMulticast(), true)
		if f.Type == "mdns" {
			f.MDNS = ParseMDNS(l4[8:])
		}
	case dst.IsMulticast():
		f.Type = "stream"
	}
}

// udpType classifies a group-addressed UDP datagram by its ports; what is
// left is "stream" for a multicast group and "other" for a broadcast (the
// U6 Pro reports 239.x/ff12:: application groups as stream and subnet
// broadcasts as other).
func udpType(sport, dport int, multicast, v6 bool) string {
	switch {
	case dport == 5353 || sport == 5353 && multicast:
		return "mdns"
	case dport == 1900:
		return "ssdp"
	case dport == 10001:
		return "ubnt"
	case !v6 && (dport == 67 || dport == 68):
		return "dhcp"
	case v6 && (dport == 547 || dport == 546):
		return "dhcpv6"
	case multicast:
		return "stream"
	}
	return "other"
}

// igmp reads joins and leaves from an IGMPv1/v2/v3 message.
func igmp(f *Frame, b []byte) {
	if len(b) < 8 {
		return
	}
	switch b[0] {
	case 0x12, 0x16: // v1/v2 membership report
		f.Join = append(f.Join, netip.AddrFrom4([4]byte(b[4:8])))
	case 0x17: // v2 leave group
		f.Leave = append(f.Leave, netip.AddrFrom4([4]byte(b[4:8])))
	case 0x22: // v3 membership report
		n := int(binary.BigEndian.Uint16(b[6:8]))
		r := b[8:]
		for i := 0; i < n && len(r) >= 8; i++ {
			typ, aux, nsrc := r[0], int(r[1])*4, int(binary.BigEndian.Uint16(r[2:4]))
			g := netip.AddrFrom4([4]byte(r[4:8]))
			recordJoinLeave(f, typ, nsrc, g)
			skip := 8 + nsrc*4 + aux
			if len(r) < skip {
				return
			}
			r = r[skip:]
		}
	}
}

// mld reads joins and leaves from an MLDv1/v2 message (b starts at the
// ICMPv6 header).
func mld(f *Frame, b []byte) {
	switch b[0] {
	case 131, 132: // v1 report, done
		if len(b) < 24 {
			return
		}
		g := netip.AddrFrom16([16]byte(b[8:24]))
		if b[0] == 131 {
			f.Join = append(f.Join, g)
		} else {
			f.Leave = append(f.Leave, g)
		}
	case 143: // v2 report
		if len(b) < 8 {
			return
		}
		n := int(binary.BigEndian.Uint16(b[6:8]))
		r := b[8:]
		for i := 0; i < n && len(r) >= 20; i++ {
			typ, aux, nsrc := r[0], int(r[1])*4, int(binary.BigEndian.Uint16(r[2:4]))
			g := netip.AddrFrom16([16]byte(r[4:20]))
			recordJoinLeave(f, typ, nsrc, g)
			skip := 20 + nsrc*16 + aux
			if len(r) < skip {
				return
			}
			r = r[skip:]
		}
	}
}

// recordJoinLeave applies one IGMPv3/MLDv2 group record (RFC 3376 4.2.12):
// EXCLUDE mode (2, 4) is a join; INCLUDE mode with sources (1, 3, 5) is a
// join; TO_IN with no sources (3, 0) is a leave; BLOCK (6) changes nothing
// we track.
func recordJoinLeave(f *Frame, typ byte, nsrc int, g netip.Addr) {
	switch {
	case typ == 2 || typ == 4:
		f.Join = append(f.Join, g)
	case typ == 3 && nsrc == 0:
		f.Leave = append(f.Leave, g)
	case (typ == 1 || typ == 3 || typ == 5) && nsrc > 0:
		f.Join = append(f.Join, g)
	}
}

func mac(b []byte) string {
	const hx = "0123456789abcdef"
	var s strings.Builder
	s.Grow(17)
	for i, c := range b {
		if i > 0 {
			s.WriteByte(':')
		}
		s.WriteByte(hx[c>>4])
		s.WriteByte(hx[c&0xf])
	}
	return s.String()
}
