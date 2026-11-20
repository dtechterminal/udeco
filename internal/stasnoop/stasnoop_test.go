// SPDX-License-Identifier: GPL-2.0-or-later

package stasnoop

import (
	"context"
	"encoding/binary"
	"net"
	"sync"
	"testing"
	"time"
)

const (
	sta = "d2:f7:e5:58:6f:89"
	gw  = "9c:05:d6:00:00:01"
)

func mac(s string) []byte { m, _ := net.ParseMAC(s); return m }
func ip4(s string) []byte { return net.ParseIP(s).To4() }

func eth(dst, src string, typ uint16, payload []byte) []byte {
	b := append(append(mac(dst), mac(src)...), byte(typ>>8), byte(typ))
	return append(b, payload...)
}

func arp(op uint16, sha, spa, tha, tpa string) []byte {
	b := []byte{0, 1, 8, 0, 6, 4, byte(op >> 8), byte(op)}
	b = append(b, mac(sha)...)
	b = append(b, ip4(spa)...)
	b = append(b, mac(tha)...)
	return append(b, ip4(tpa)...)
}

// udp4 is an IPv4/UDP packet (no options unless ihl > 5).
func udp4(src, dst string, sport, dport uint16, frag uint16, ihl int, payload []byte) []byte {
	h := make([]byte, ihl*4)
	h[0] = 0x40 | byte(ihl)
	binary.BigEndian.PutUint16(h[2:], uint16(len(h)+8+len(payload)))
	binary.BigEndian.PutUint16(h[6:], frag)
	h[8], h[9] = 64, 17
	copy(h[12:], ip4(src))
	copy(h[16:], ip4(dst))
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	return append(append(h, u...), payload...)
}

func dhcp(op byte, xid uint32, chaddr, yiaddr string, msgType byte) []byte {
	b := make([]byte, 240)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	copy(b[16:], ip4(yiaddr))
	copy(b[28:], mac(chaddr))
	copy(b[236:], []byte{99, 130, 83, 99})
	b = append(b, 12, 3, 'x', 'y', 'z') // hostname first
	b = append(b, 53, 1, msgType, 255)
	return b
}

func dns(id uint16, response bool, rcode byte) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b, id)
	if response {
		b[2] = 0x81
		b[3] = 0x80 | rcode
	} else {
		b[2] = 0x01
	}
	return b
}

func TestParse(t *testing.T) {
	bcast := "ff:ff:ff:ff:ff:ff"
	for name, tc := range map[string]struct {
		frame []byte
		out   bool
		want  Obs
		ok    bool
	}{
		"arp request from the station": {eth(bcast, sta, 0x0806, arp(1, sta, "192.168.1.50", "00:00:00:00:00:00", "192.168.1.1")), false,
			Obs{Kind: ARPRequest, Src: sta, Dst: bcast, SrcIP: "192.168.1.50", DstIP: "192.168.1.1"}, true},
		"arp reply from the gateway": {eth(sta, gw, 0x0806, arp(2, gw, "192.168.1.1", sta, "192.168.1.50")), true,
			Obs{Kind: ARPReply, Out: true, Src: gw, Dst: sta, SrcIP: "192.168.1.1", DstIP: "192.168.1.50"}, true},
		"dhcp discover": {eth(bcast, sta, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, 0, 5, dhcp(1, 0xabcd, sta, "0.0.0.0", 1))), false,
			Obs{Kind: DHCPDiscover, Src: sta, Dst: bcast, SrcIP: "0.0.0.0", DstIP: "255.255.255.255", Client: sta, ID: 0xabcd}, true},
		"dhcp ack": {eth(sta, gw, 0x0800, udp4("192.168.1.1", "192.168.1.50", 67, 68, 0, 5, dhcp(2, 0xabcd, sta, "192.168.1.50", 5))), true,
			Obs{Kind: DHCPAck, Out: true, Src: gw, Dst: sta, SrcIP: "192.168.1.1", DstIP: "192.168.1.50", Client: sta, YourIP: "192.168.1.50", ID: 0xabcd}, true},
		"dhcp nak (ip options)": {eth(sta, gw, 0x0800, udp4("192.168.1.1", "255.255.255.255", 67, 68, 0x4000, 6, dhcp(2, 7, sta, "0.0.0.0", 6))), true,
			Obs{Kind: DHCPNak, Out: true, Src: gw, Dst: sta, SrcIP: "192.168.1.1", DstIP: "255.255.255.255", Client: sta, YourIP: "0.0.0.0", ID: 7}, true},
		"dns query": {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0, 5, dns(0x1234, false, 0))), false,
			Obs{Kind: DNSQuery, Src: sta, Dst: gw, SrcIP: "192.168.1.50", DstIP: "192.168.1.1", ID: 0x1234}, true},
		"dns response": {eth(sta, gw, 0x0800, udp4("192.168.1.1", "192.168.1.50", 53, 50000, 0, 5, dns(0x1234, true, 3))), true,
			Obs{Kind: DNSResponse, Out: true, Src: gw, Dst: sta, SrcIP: "192.168.1.1", DstIP: "192.168.1.50", ID: 0x1234}, true},
		"fragment":     {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0x2000, 5, dns(1, false, 0))), false, Obs{}, false},
		"short dns":    {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0, 5, []byte{1, 2})), false, Obs{}, false},
		"other udp":    {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 443, 0, 5, dns(1, false, 0))), false, Obs{}, false},
		"short dhcp":   {eth(bcast, sta, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, 0, 5, make([]byte, 100))), false, Obs{}, false},
		"no cookie":    {eth(bcast, sta, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, 0, 5, make([]byte, 244))), false, Obs{}, false},
		"short arp":    {eth(bcast, sta, 0x0806, []byte{0, 1, 8, 0}), false, Obs{}, false},
		"ipv6":         {eth(bcast, sta, 0x86dd, make([]byte, 60)), false, Obs{}, false},
		"runt":         {[]byte{1, 2, 3}, false, Obs{}, false},
		"truncated ip": {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0, 5, dns(1, false, 0))[:20]), false, Obs{}, false},
	} {
		got, ok := Parse(tc.frame, tc.out)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("%s: %+v %v, want %+v", name, got, ok, tc.want)
		}
	}
}

// The station a frame is about: the sender of what it sent, the receiver
// of what the AP sent to it, the DHCP client for DHCP.
func TestStation(t *testing.T) {
	for _, tc := range []struct {
		o    Obs
		want string
	}{
		{Obs{Kind: DNSQuery, Src: sta, Dst: gw}, sta},
		{Obs{Kind: DNSResponse, Out: true, Src: gw, Dst: sta}, sta},
		{Obs{Kind: DHCPAck, Out: true, Src: gw, Dst: "ff:ff:ff:ff:ff:ff", Client: sta}, sta},
		{Obs{Kind: ARPReply, Out: true, Src: gw, Dst: "ff:ff:ff:ff:ff:ff"}, ""},
	} {
		if got := tc.o.Station(); got != tc.want {
			t.Errorf("%+v: %q", tc.o, got)
		}
	}
}

// vm runs the classic BPF instructions the filter uses.
func vm(t *testing.T, prog []Insn, pkt []byte) uint32 {
	t.Helper()
	var a, x uint32
	ld := func(off uint32, n int) (uint32, bool) {
		if int(off)+n > len(pkt) {
			return 0, false
		}
		var v uint32
		for i := 0; i < n; i++ {
			v = v<<8 | uint32(pkt[int(off)+i])
		}
		return v, true
	}
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		var ok = true
		switch in.Code {
		case 0x28: // ldh abs
			a, ok = ld(in.K, 2)
		case 0x30: // ldb abs
			a, ok = ld(in.K, 1)
		case 0x48: // ldh ind
			a, ok = ld(x+in.K, 2)
		case 0x50: // ldb ind
			a, ok = ld(x+in.K, 1)
		case 0x54: // and k
			a &= in.K
		case 0xb1: // ldxb msh
			var v uint32
			v, ok = ld(in.K, 1)
			x = 4 * (v & 0xf)
		case 0x15: // jeq
			if a == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x45: // jset
			if a&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x06:
			return in.K
		default:
			t.Fatalf("opcode %#x", in.Code)
		}
		if !ok {
			return 0
		}
	}
	t.Fatal("fell off the program")
	return 0
}

// The socket filter passes ARP, unfragmented IPv4 UDP to or from ports 53,
// 67 and 68 (with or without IP options), and nothing else.
func TestFilter(t *testing.T) {
	bcast := "ff:ff:ff:ff:ff:ff"
	for name, tc := range map[string]struct {
		frame []byte
		pass  bool
	}{
		"arp":           {eth(bcast, sta, 0x0806, arp(1, sta, "192.168.1.50", "00:00:00:00:00:00", "192.168.1.1")), true},
		"dns query":     {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0, 5, dns(1, false, 0))), true},
		"dns response":  {eth(sta, gw, 0x0800, udp4("192.168.1.1", "192.168.1.50", 53, 50000, 0x4000, 5, dns(1, true, 0))), true},
		"dhcp options":  {eth(bcast, sta, 0x0800, udp4("0.0.0.0", "255.255.255.255", 68, 67, 0, 7, dhcp(1, 1, sta, "0.0.0.0", 1))), true},
		"dhcp server":   {eth(sta, gw, 0x0800, udp4("192.168.1.1", "192.168.1.50", 67, 68, 0, 5, dhcp(2, 1, sta, "192.168.1.50", 5))), true},
		"https":         {eth(gw, sta, 0x0800, udp4("192.168.1.50", "1.1.1.1", 50000, 443, 0, 5, nil)), false},
		"fragment":      {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0x2001, 5, nil)), false},
		"more frags":    {eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0x2000, 5, nil)), true},
		"tcp":           {eth(gw, sta, 0x0800, func() []byte { p := udp4("192.168.1.50", "192.168.1.1", 50000, 53, 0, 5, nil); p[9] = 6; return p }()), false},
		"ipv6":          {eth(bcast, sta, 0x86dd, make([]byte, 60)), false},
		"truncated arp": {eth(bcast, sta, 0x0806, nil)[:12], false},
	} {
		got := vm(t, filter, tc.frame)
		if (got != 0) != tc.pass {
			t.Errorf("%s: %d", name, got)
		}
	}
}

// The ring keeps the newest Max observations and counts the others.
func TestRing(t *testing.T) {
	r := NewRing(3)
	for i := 0; i < 5; i++ {
		r.Add(Obs{ID: uint32(i)})
	}
	got, dropped := r.Take()
	if len(got) != 3 || got[0].ID != 2 || got[2].ID != 4 || dropped != 2 {
		t.Fatalf("%+v %d", got, dropped)
	}
	if got, dropped := r.Take(); len(got) != 0 || dropped != 0 {
		t.Fatalf("second take %v %d", got, dropped)
	}
}

type fakeSrc struct {
	mu     sync.Mutex
	frames [][]byte
	outs   []bool
	closed bool
}

func (s *fakeSrc) Recv(b []byte) (int, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.frames) == 0 {
		time.Sleep(time.Millisecond)
		return 0, false, ErrTimeout
	}
	f, o := s.frames[0], s.outs[0]
	s.frames, s.outs = s.frames[1:], s.outs[1:]
	return copy(b, f), o, nil
}

func (s *fakeSrc) Close() error { s.mu.Lock(); s.closed = true; s.mu.Unlock(); return nil }

// Run tags what it parses with the VAP and the time, skips the rest, and
// closes the source when the context ends.
func TestRun(t *testing.T) {
	src := &fakeSrc{
		frames: [][]byte{eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 1, 53, 0, 5, dns(9, false, 0))), {1, 2, 3}},
		outs:   []bool{false, false},
	}
	r := NewRing(10)
	ctx, cancel := context.WithCancel(context.Background())
	at := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	done := make(chan error)
	go func() { done <- Run(ctx, r, "wl12", src, func() time.Time { return at }) }()
	var got []Obs
	for i := 0; i < 1000 && len(got) == 0; i++ {
		o, _ := r.Take()
		got = append(got, o...)
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Vif != "wl12" || got[0].At != at || got[0].Kind != DNSQuery || got[0].ID != 9 {
		t.Fatalf("%+v", got)
	}
	if !src.closed {
		t.Error("source not closed")
	}
}

// A gratuitous ARP on a station's behalf: a broadcast ARP request from its
// MAC whose sender and target address are its own.
func TestGARP(t *testing.T) {
	f, err := GARP(sta, "192.168.1.50")
	if err != nil {
		t.Fatal(err)
	}
	o, ok := Parse(f, false)
	if !ok || o.Kind != ARPRequest || o.Src != sta || o.Dst != "ff:ff:ff:ff:ff:ff" || o.SrcIP != "192.168.1.50" || o.DstIP != "192.168.1.50" {
		t.Fatalf("%+v %v", o, ok)
	}
	if len(f) < 60 {
		t.Errorf("runt frame: %d bytes", len(f))
	}
	for _, bad := range [][2]string{{"x", "192.168.1.50"}, {sta, "fe80::1"}, {sta, ""}, {"ff:ff:ff:ff:ff:ff", "192.168.1.50"}, {sta, "0.0.0.0"}} {
		if _, err := GARP(bad[0], bad[1]); err == nil {
			t.Errorf("GARP(%q, %q) accepted", bad[0], bad[1])
		}
	}
}

const (
	sta6 = "2001:db8:1::50"
	res6 = "2001:db8:1::1"
)

// ext6 is one IPv6 extension header: its type and its body after the
// next-header and length octets (6 + 8n bytes).
type ext6 struct {
	typ  byte
	body []byte
}

// ip6 is an IPv6 packet: the fixed header, the extension headers in
// order, then the upper-layer header and data (protocol proto).
func ip6(src, dst string, exts []ext6, proto byte, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	h[7] = 64
	copy(h[8:], net.ParseIP(src).To16())
	copy(h[24:], net.ParseIP(dst).To16())
	var chain []byte
	nh := &h[6]
	for _, e := range exts {
		*nh = e.typ
		b := append([]byte{0, byte((len(e.body)+2)/8 - 1)}, e.body...)
		if e.typ == 44 {
			b[1] = 0 // the fragment header's second octet is reserved
		}
		chain = append(chain, b...)
		nh = &chain[len(chain)-len(b)]
	}
	*nh = proto
	p := append(append(h, chain...), l4...)
	binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
	return p
}

func udp(sport, dport uint16, payload []byte) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], uint16(8+len(payload)))
	return append(u, payload...)
}

// tcp is a bare TCP header (no options) with flags (0x02 SYN, 0x10 ACK).
func tcp(sport, dport uint16, flags byte) []byte {
	t := make([]byte, 20)
	binary.BigEndian.PutUint16(t[0:], sport)
	binary.BigEndian.PutUint16(t[2:], dport)
	t[12], t[13] = 5<<4, flags
	binary.BigEndian.PutUint16(t[14:], 64240)
	return t
}

// tcp4 is an IPv4/TCP packet.
func tcp4(src, dst string, sport, dport uint16, flags byte, frag uint16) []byte {
	p := udp4(src, dst, 0, 0, frag, 5, nil)[:20]
	p[9] = 6
	binary.BigEndian.PutUint16(p[2:], 40)
	return append(p, tcp(sport, dport, flags)...)
}

var (
	hbh  = ext6{0, []byte{1, 4, 0, 0, 0, 0}}                           // hop-by-hop, PadN
	dst6 = ext6{60, []byte{1, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}} // destination options, 16 bytes
	rt0  = ext6{43, []byte{4, 0, 0, 0, 0, 0}}                          // routing, segments left 0
	frg  = ext6{44, []byte{0, 1, 0, 0, 0, 1}}                          // fragment, offset 0, more fragments
	frg1 = ext6{44, []byte{0, 0x08, 0, 0, 0, 1}}                       // fragment, offset 1, last
)

// IPv6 DNS is read like IPv4 DNS: the transaction id and both addresses,
// across hop-by-hop, routing and destination-options headers; a fragment
// (any fragment header) is never whole and is dropped. DHCP ports over
// IPv6 are not DHCP.
func TestParseIPv6(t *testing.T) {
	q := func(exts ...ext6) []byte {
		return eth(gw, sta, 0x86dd, ip6(sta6, res6, exts, 17, udp(50000, 53, dns(0x1234, false, 0))))
	}
	query := Obs{Kind: DNSQuery, V6: true, Src: sta, Dst: gw, SrcIP: sta6, DstIP: res6, ID: 0x1234}
	truncated := q(dst6)
	truncated = truncated[:14+40+8] // the destination options header cut short
	for name, tc := range map[string]struct {
		frame []byte
		out   bool
		want  Obs
		ok    bool
	}{
		"query": {q(), false, query, true},
		"response": {eth(sta, gw, 0x86dd, ip6(res6, sta6, nil, 17, udp(53, 50000, dns(0x1234, true, 2)))), true,
			Obs{Kind: DNSResponse, V6: true, Out: true, Src: gw, Dst: sta, SrcIP: res6, DstIP: sta6, ID: 0x1234}, true},
		"link-local resolver": {eth(gw, sta, 0x86dd, ip6("fe80::50", "fe80::1", nil, 17, udp(40000, 53, dns(9, false, 0)))), false,
			Obs{Kind: DNSQuery, V6: true, Src: sta, Dst: gw, SrcIP: "fe80::50", DstIP: "fe80::1", ID: 9}, true},
		"hop-by-hop":                   {q(hbh), false, query, true},
		"hop-by-hop, routing, dstopts": {q(hbh, rt0, dst6), false, query, true},
		"fragment":                     {q(frg), false, Obs{}, false},
		"later fragment":               {q(frg1), false, Obs{}, false},
		"fragment after hop-by-hop":    {q(hbh, frg), false, Obs{}, false},
		"truncated extension":          {truncated, false, Obs{}, false},
		"truncated fixed header":       {q()[:14+39], false, Obs{}, false},
		"version 4 in an ipv6 frame":   {func() []byte { f := q(); f[14] = 0x40; return f }(), false, Obs{}, false},
		"short dns":                    {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 17, udp(50000, 53, []byte{1, 2}))), false, Obs{}, false},
		"other udp":                    {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 17, udp(50000, 443, dns(1, false, 0)))), false, Obs{}, false},
		"dhcp ports":                   {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 17, udp(68, 67, dhcp(1, 1, sta, "0.0.0.0", 1)))), false, Obs{}, false},
		"icmpv6 after hop-by-hop":      {eth(gw, sta, 0x86dd, ip6(sta6, "ff02::16", []ext6{hbh}, 58, make([]byte, 28))), false, Obs{}, false},
		"udp header cut":               {q()[:14+40+6], false, Obs{}, false},
	} {
		got, ok := Parse(tc.frame, tc.out)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("%s: %+v %v, want %+v", name, got, ok, tc.want)
		}
	}
}

// DNS over TLS cannot be read, only seen: a station's SYN to port 853 and
// the server's SYN-ACK back, over IPv4 or IPv6. Anything else on TCP is
// not an observation.
func TestParseDoT(t *testing.T) {
	for name, tc := range map[string]struct {
		frame []byte
		out   bool
		want  Obs
		ok    bool
	}{
		"syn v4": {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "8.8.8.8", 41000, 853, 0x02, 0x4000)), false,
			Obs{Kind: DoTSyn, Src: sta, Dst: gw, SrcIP: "192.168.1.50", DstIP: "8.8.8.8"}, true},
		"syn-ack v4": {eth(sta, gw, 0x0800, tcp4("8.8.8.8", "192.168.1.50", 853, 41000, 0x12, 0)), true,
			Obs{Kind: DoTSynAck, Out: true, Src: gw, Dst: sta, SrcIP: "8.8.8.8", DstIP: "192.168.1.50"}, true},
		"syn v6": {eth(gw, sta, 0x86dd, ip6(sta6, "2001:4860:4860::8888", nil, 6, tcp(41000, 853, 0x02))), false,
			Obs{Kind: DoTSyn, V6: true, Src: sta, Dst: gw, SrcIP: sta6, DstIP: "2001:4860:4860::8888"}, true},
		"syn-ack v6": {eth(sta, gw, 0x86dd, ip6("2001:4860:4860::8888", sta6, nil, 6, tcp(853, 41000, 0x12))), true,
			Obs{Kind: DoTSynAck, V6: true, Out: true, Src: gw, Dst: sta, SrcIP: "2001:4860:4860::8888", DstIP: sta6}, true},
		"ack v4":          {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "8.8.8.8", 41000, 853, 0x10, 0)), false, Obs{}, false},
		"syn to 443":      {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "8.8.8.8", 41000, 443, 0x02, 0)), false, Obs{}, false},
		"syn from 853":    {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "8.8.8.8", 853, 41000, 0x02, 0)), false, Obs{}, false},
		"tcp fragment v4": {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "8.8.8.8", 41000, 853, 0x02, 0x2000)), false, Obs{}, false},
		"short tcp":       {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "8.8.8.8", 41000, 853, 0x02, 0)[:20+12]), false, Obs{}, false},
	} {
		got, ok := Parse(tc.frame, tc.out)
		if ok != tc.ok || ok && got != tc.want {
			t.Errorf("%s: %+v %v, want %+v", name, got, ok, tc.want)
		}
	}
}

// The socket filter also passes IPv6 UDP from or to port 53, IPv6
// packets with a hop-by-hop, routing or destination-options header first
// (Parse walks those), and TCP SYNs from or to port 853 over either
// family; IPv6 fragments and everything else stay in the kernel.
func TestFilterIPv6AndDoT(t *testing.T) {
	q := func(exts ...ext6) []byte {
		return eth(gw, sta, 0x86dd, ip6(sta6, res6, exts, 17, udp(50000, 53, dns(1, false, 0))))
	}
	for name, tc := range map[string]struct {
		frame []byte
		pass  bool
	}{
		"v6 query":           {q(), true},
		"v6 response":        {eth(sta, gw, 0x86dd, ip6(res6, sta6, nil, 17, udp(53, 50000, dns(1, true, 0)))), true},
		"v6 hop-by-hop":      {q(hbh), true},
		"v6 routing":         {q(rt0), true},
		"v6 dstopts":         {q(dst6), true},
		"v6 fragment":        {q(frg), false},
		"v6 other udp":       {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 17, udp(50000, 443, nil))), false},
		"v6 dhcpv6":          {eth(gw, sta, 0x86dd, ip6("fe80::50", "ff02::1:2", nil, 17, udp(546, 547, make([]byte, 20)))), false},
		"v6 icmpv6":          {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 58, make([]byte, 24))), false},
		"v6 tcp 853 syn":     {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 6, tcp(41000, 853, 0x02))), true},
		"v6 tcp 853 syn-ack": {eth(sta, gw, 0x86dd, ip6(res6, sta6, nil, 6, tcp(853, 41000, 0x12))), true},
		"v6 tcp 853 ack":     {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 6, tcp(41000, 853, 0x10))), false},
		"v6 tcp 443 syn":     {eth(gw, sta, 0x86dd, ip6(sta6, res6, nil, 6, tcp(41000, 443, 0x02))), false},
		"v6 truncated":       {q()[:14+30], false},
		"v4 tcp 853 syn":     {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "1.1.1.1", 41000, 853, 0x02, 0x4000)), true},
		"v4 tcp 853 syn-ack": {eth(sta, gw, 0x0800, tcp4("1.1.1.1", "192.168.1.50", 853, 41000, 0x12, 0)), true},
		"v4 tcp 853 ack":     {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "1.1.1.1", 41000, 853, 0x10, 0)), false},
		"v4 tcp 443 syn":     {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "1.1.1.1", 41000, 443, 0x02, 0)), false},
		"v4 tcp fragment":    {eth(gw, sta, 0x0800, tcp4("192.168.1.50", "1.1.1.1", 41000, 853, 0x02, 0x0001)), false},
	} {
		got := vm(t, filter, tc.frame)
		if (got != 0) != tc.pass {
			t.Errorf("%s: %d", name, got)
		}
	}
}

// filterV4 is the filter as it was before IPv6 and DoT: ARP and IPv4 UDP
// from or to 53, 67 and 68.
var filterV4 = []Insn{
	{Code: 0x28, K: 12}, {Code: 0x15, Jt: 14, K: 0x0806}, {Code: 0x15, Jf: 14, K: 0x0800},
	{Code: 0x30, K: 23}, {Code: 0x15, Jf: 12, K: 17}, {Code: 0x28, K: 20}, {Code: 0x45, Jt: 10, K: 0x1fff},
	{Code: 0xb1, K: 14}, {Code: 0x48, K: 14}, {Code: 0x15, Jt: 6, K: 53}, {Code: 0x15, Jt: 5, K: 67},
	{Code: 0x15, Jt: 4, K: 68}, {Code: 0x48, K: 16}, {Code: 0x15, Jt: 2, K: 53}, {Code: 0x15, Jt: 1, K: 67},
	{Code: 0x15, Jt: 0, Jf: 1, K: 68}, {Code: 0x06, K: snap}, {Code: 0x06, K: 0},
}

// IPv4 regression: on ARP and every IPv4 UDP frame, and on IPv4 TCP away
// from port 853, the filter decides exactly as before; Parse reads the
// same frames the same way (never as IPv6).
func TestFilterIPv4Unchanged(t *testing.T) {
	var frames [][]byte
	ports := []uint16{0, 53, 67, 68, 80, 123, 443, 853, 5353}
	for _, sp := range ports {
		for _, dp := range ports {
			for _, frag := range []uint16{0, 0x4000, 0x2000, 0x2001, 0x0001} {
				for _, ihl := range []int{5, 6, 15} {
					frames = append(frames,
						eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", sp, dp, frag, ihl, dns(1, false, 0))),
						eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", sp, dp, frag, ihl, nil)))
				}
			}
			if sp != 853 && dp != 853 {
				frames = append(frames, eth(gw, sta, 0x0800, tcp4("192.168.1.50", "1.1.1.1", sp, dp, 0x02, 0)))
			}
		}
	}
	frames = append(frames,
		eth("ff:ff:ff:ff:ff:ff", sta, 0x0806, arp(1, sta, "192.168.1.50", "00:00:00:00:00:00", "192.168.1.1")),
		eth("ff:ff:ff:ff:ff:ff", sta, 0x0806, nil)[:12],
		eth(gw, sta, 0x0800, udp4("192.168.1.50", "192.168.1.1", 1, 53, 0, 5, nil))[:30],
		eth(gw, sta, 0x88cc, make([]byte, 40)))
	for i, f := range frames {
		if a, b := vm(t, filter, f), vm(t, filterV4, f); a != b {
			t.Errorf("frame %d: %d, was %d", i, a, b)
		}
		if o, ok := Parse(f, false); ok && o.V6 {
			t.Errorf("frame %d read as IPv6: %+v", i, o)
		}
	}
}
