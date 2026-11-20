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
