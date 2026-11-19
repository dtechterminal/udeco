// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"encoding/binary"
	"net/netip"
)

// Ethernet frames carrying mDNS: IPv4 to 224.0.0.251 or IPv6 to ff02::fb,
// UDP 5353 -> 5353, unfragmented. The socket hands frames over untagged
// (the kernel moves an 802.1Q tag into the packet's metadata before the
// taps run); a tag for a virtual port is added on send (raw_linux.go).

const (
	mdnsPort = 5353
	etherIP4 = 0x0800
	etherIP6 = 0x86dd
	maxFrame = 1514 // no jumbo frames: Wi-Fi and the uplink run MTU 1500
)

var (
	group4  = netip.MustParseAddr("224.0.0.251")
	group6  = netip.MustParseAddr("ff02::fb")
	mac4    = [6]byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}
	mac6    = [6]byte{0x33, 0x33, 0x00, 0x00, 0x00, 0xfb}
	zeroMAC [6]byte
)

// packet is a parsed mDNS frame.
type packet struct {
	src     [6]byte
	v6      bool
	ipSrc   netip.Addr
	tos     byte   // IPv4 TOS / IPv6 traffic class
	flow    uint32 // IPv6 flow label
	ttl     byte   // IPv4 TTL / IPv6 hop limit
	ipID    uint16
	payload []byte // the DNS message
}

// parseFrame validates an mDNS frame. It returns false for anything else:
// another group, port or protocol, a fragment, IP options or IPv6
// extension headers, a bad length or checksum.
func parseFrame(f []byte) (packet, bool) {
	var p packet
	if len(f) < 14 || len(f) > maxFrame {
		return p, false
	}
	copy(p.src[:], f[6:12])
	if p.src[0]&1 != 0 || p.src == zeroMAC {
		return p, false // group or zero source address
	}
	var l4 []byte
	var src, dst netip.Addr
	switch binary.BigEndian.Uint16(f[12:]) {
	case etherIP4:
		ip := f[14:]
		if len(ip) < 20 || ip[0] != 0x45 || ip[9] != 17 {
			return p, false
		}
		tl := int(binary.BigEndian.Uint16(ip[2:]))
		if tl < 28 || tl > len(ip) || binary.BigEndian.Uint16(ip[6:])&0x3fff != 0 {
			return p, false // short, or a fragment (MF or an offset)
		}
		if csum(0, ip[:20]) != 0 {
			return p, false
		}
		src, dst = netip.AddrFrom4([4]byte(ip[12:16])), netip.AddrFrom4([4]byte(ip[16:20]))
		if dst != group4 {
			return p, false
		}
		p.tos, p.ttl, p.ipID = ip[1], ip[8], binary.BigEndian.Uint16(ip[4:])
		l4 = ip[20:tl]
	case etherIP6:
		ip := f[14:]
		if len(ip) < 48 || ip[0]>>4 != 6 || ip[6] != 17 {
			return p, false
		}
		pl := int(binary.BigEndian.Uint16(ip[4:]))
		if pl < 8 || 40+pl > len(ip) {
			return p, false
		}
		src, dst = netip.AddrFrom16([16]byte(ip[8:24])), netip.AddrFrom16([16]byte(ip[24:40]))
		if dst != group6 {
			return p, false
		}
		vtf := binary.BigEndian.Uint32(ip)
		p.v6, p.tos, p.flow, p.ttl = true, byte(vtf>>20), vtf&0xfffff, ip[7]
		l4 = ip[40 : 40+pl]
	default:
		return p, false
	}
	if len(l4) < 8 || binary.BigEndian.Uint16(l4) != mdnsPort || binary.BigEndian.Uint16(l4[2:]) != mdnsPort {
		return p, false // legacy unicast queries (another source port) are not bridged
	}
	ul := int(binary.BigEndian.Uint16(l4[4:]))
	if ul < 8 || ul > len(l4) {
		return p, false
	}
	if c := binary.BigEndian.Uint16(l4[6:]); c != 0 || p.v6 {
		if c == 0 || udpSum(src, dst, l4[:ul]) != 0 {
			return p, false
		}
	}
	p.ipSrc, p.payload = src, l4[8:ul]
	return p, true
}

// csum is the one's complement sum of b folded into sum (RFC 1071),
// complemented.
func csum(sum uint32, b []byte) uint16 {
	for len(b) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// udpSum is the UDP checksum over the pseudo-header and the datagram u
// (0 for a datagram whose checksum field is right).
func udpSum(src, dst netip.Addr, u []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
	}
	s, d := src.AsSlice(), dst.AsSlice()
	add(s)
	add(d)
	sum += 17 + uint32(len(u))
	return csum(sum, u)
}

// build makes the frame for payload with p's addresses, TTL and source MAC.
func (p packet) build(payload []byte) ([]byte, bool) {
	var f []byte
	ul := 8 + len(payload)
	if p.v6 {
		if 14+40+ul > maxFrame {
			return nil, false
		}
		f = make([]byte, 14+40+ul)
		copy(f, mac6[:])
		binary.BigEndian.PutUint16(f[12:], etherIP6)
		ip := f[14:]
		binary.BigEndian.PutUint32(ip, 6<<28|uint32(p.tos)<<20|p.flow&0xfffff)
		binary.BigEndian.PutUint16(ip[4:], uint16(ul))
		ip[6], ip[7] = 17, p.ttl
		copy(ip[8:24], p.ipSrc.AsSlice())
		copy(ip[24:40], group6.AsSlice())
	} else {
		if 14+20+ul > maxFrame {
			return nil, false
		}
		f = make([]byte, 14+20+ul)
		copy(f, mac4[:])
		binary.BigEndian.PutUint16(f[12:], etherIP4)
		ip := f[14:]
		ip[0], ip[1] = 0x45, p.tos
		binary.BigEndian.PutUint16(ip[2:], uint16(20+ul))
		binary.BigEndian.PutUint16(ip[4:], p.ipID)
		ip[8], ip[9] = p.ttl, 17
		copy(ip[12:16], p.ipSrc.AsSlice())
		copy(ip[16:20], group4.AsSlice())
		binary.BigEndian.PutUint16(ip[10:], csum(0, ip[:20]))
	}
	copy(f[6:12], p.src[:])
	u := f[len(f)-ul:]
	binary.BigEndian.PutUint16(u, mdnsPort)
	binary.BigEndian.PutUint16(u[2:], mdnsPort)
	binary.BigEndian.PutUint16(u[4:], uint16(ul))
	copy(u[8:], payload)
	dst := group4
	if p.v6 {
		dst = group6
	}
	c := udpSum(p.ipSrc, dst, u)
	if c == 0 {
		c = 0xffff
	}
	binary.BigEndian.PutUint16(u[6:], c)
	return f, true
}
