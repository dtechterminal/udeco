// SPDX-License-Identifier: GPL-2.0-or-later

package mcinspect

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

var (
	staA    = []byte{0x02, 0, 0, 0, 0, 0xa1}
	staB    = []byte{0x02, 0, 0, 0, 0, 0xb2}
	gw      = []byte{0x02, 0, 0, 0, 0, 0x01}
	bcast   = []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	mdnsMAC = []byte{0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb}
	t0      = time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
)

func eth(dst, src []byte, et uint16, payload []byte) []byte {
	b := append(append(append([]byte{}, dst...), src...), byte(et>>8), byte(et))
	return append(b, payload...)
}

func ip4(proto byte, src, dst string, l4 []byte) []byte {
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 1, proto
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(l4)))
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(h[12:], s[:])
	copy(h[16:], d[:])
	return append(h, l4...)
}

func ip6(next byte, src, dst string, l4 []byte) []byte {
	h := make([]byte, 40)
	h[0], h[6], h[7] = 0x60, next, 1
	binary.BigEndian.PutUint16(h[4:], uint16(len(l4)))
	s, d := netip.MustParseAddr(src).As16(), netip.MustParseAddr(dst).As16()
	copy(h[8:], s[:])
	copy(h[24:], d[:])
	return append(h, l4...)
}

func udp(sport, dport int, payload []byte) []byte {
	h := make([]byte, 8)
	binary.BigEndian.PutUint16(h[0:], uint16(sport))
	binary.BigEndian.PutUint16(h[2:], uint16(dport))
	binary.BigEndian.PutUint16(h[4:], uint16(8+len(payload)))
	return append(h, payload...)
}

// dnsName encodes a name in labels.
func dnsName(n string) []byte {
	var b []byte
	start := 0
	for i := 0; i <= len(n); i++ {
		if i == len(n) || n[i] == '.' {
			b = append(b, byte(i-start))
			b = append(b, n[start:i]...)
			start = i + 1
		}
	}
	return append(b, 0)
}

// mdnsQuery is a one-question query for name with qtype.
func mdnsQuery(name string, qtype uint16) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[4:], 1)
	b = append(b, dnsName(name)...)
	return append(b, byte(qtype>>8), byte(qtype), 0, 1)
}

// mdnsAnswer is a response with one PTR record name -> instance (the
// instance name uses a compression pointer to name) and one SRV record.
func mdnsAnswer(name string) []byte {
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[2:], 0x8400)
	binary.BigEndian.PutUint16(b[6:], 2)
	nameOff := len(b)
	b = append(b, dnsName(name)...)
	rdata := append([]byte{4, 'T', 'V', '-', '1'}, 0xc0, byte(nameOff))
	b = append(b, 0, 12, 0, 1, 0, 0, 0x11, 0x94, 0, byte(len(rdata)))
	instOff := len(b)
	b = append(b, rdata...)
	b = append(b, 0xc0, byte(instOff)) // SRV owner: the instance name
	srv := []byte{0, 0, 0, 0, 0x1f, 0x49, 0}
	b = append(b, 0, 33, 0x80, 1, 0, 0, 0, 120, 0, byte(len(srv)))
	return append(b, srv...)
}

func igmpV3(recs ...[]byte) []byte {
	b := []byte{0x22, 0, 0, 0, 0, 0, 0, byte(len(recs))}
	for _, r := range recs {
		b = append(b, r...)
	}
	return b
}

func igmpRec(typ byte, group string, srcs ...string) []byte {
	g := netip.MustParseAddr(group).As4()
	r := []byte{typ, 0, 0, byte(len(srcs)), g[0], g[1], g[2], g[3]}
	for _, s := range srcs {
		a := netip.MustParseAddr(s).As4()
		r = append(r, a[:]...)
	}
	return r
}

func mldV2(typ byte, group string) []byte {
	g := netip.MustParseAddr(group).As16()
	b := []byte{143, 0, 0, 0, 0, 0, 0, 1, typ, 0, 0, 0}
	return append(b, g[:]...)
}

// hbh wraps an ICMPv6 message behind a hop-by-hop header with a router
// alert, as MLD reports are sent.
func hbh(icmp []byte) []byte {
	return append([]byte{58, 0, 5, 2, 0, 0, 1, 0}, icmp...)
}

func observe(t *Table, vif string, frame []byte, out bool, at time.Time) {
	t.Observe(vif, frame, len(frame), out, at)
}

func block(t *testing.T, tb *Table, vif string, mac []byte, at time.Time) map[string]any {
	t.Helper()
	b, ok := tb.Block(vif, mac2s(mac), at)
	if !ok {
		t.Fatalf("Block(%s): not inspected", vif)
	}
	// through JSON, as the controller receives it
	js, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(js, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func mac2s(b []byte) string { return mac(b) }

func typeCounts(m map[string]any, ty string) [4]float64 {
	c := m["types"].(map[string]any)[ty].(map[string]any)
	return [4]float64{c["rx_bytes"].(float64), c["rx_pkts"].(float64), c["tx_bytes"].(float64), c["tx_pkts"].(float64)}
}

func findGroup(m map[string]any, typ, ip string, port float64) map[string]any {
	for _, g := range m["groups"].([]any) {
		g := g.(map[string]any)
		if g["type"] == typ && g["group_ip"] == ip && g["dst_port"] == port {
			return g
		}
	}
	return nil
}

func TestBlockShapeAndAttribution(t *testing.T) {
	tb := NewTable()
	q := eth(mdnsMAC, staA, 0x0800, ip4(17, "192.168.0.50", "224.0.0.251", udp(5353, 5353, mdnsQuery("_googlecast._tcp.local", 12))))
	observe(tb, "wl12", q, false, t0)
	arp := eth(bcast, gw, 0x0806, make([]byte, 28))
	observe(tb, "wl12", arp, true, t0)
	observe(tb, "wl12", arp, true, t0)
	// unicast frames are not multicast accounting
	observe(tb, "wl12", eth(gw, staA, 0x0800, ip4(17, "192.168.0.50", "192.168.0.1", udp(5000, 53, nil))), false, t0)

	a := block(t, tb, "wl12", staA, t0)
	types := a["types"].(map[string]any)
	if len(types) != len(Types) {
		t.Fatalf("types has %d classes, want all %d: %v", len(types), len(Types), types)
	}
	if got, want := typeCounts(a, "mdns"), [4]float64{float64(len(q)), 1, 0, 0}; got != want {
		t.Errorf("mdns = %v, want %v", got, want)
	}
	if got, want := typeCounts(a, "arp"), [4]float64{0, 0, float64(2 * len(arp)), 2}; got != want {
		t.Errorf("arp = %v, want %v (the VAP's tx)", got, want)
	}
	if got := typeCounts(a, "other"); got != [4]float64{} {
		t.Errorf("other = %v: the unicast frame was counted", got)
	}
	g := findGroup(a, "mdns", "224.0.0.251", 5353)
	if g == nil || g["rx_pkts"] != 1.0 || g["tx_pkts"] != nil {
		t.Errorf("mdns group = %v, want rx only", g)
	}
	if g := findGroup(a, "arp", "0.0.0.0", 0); g == nil || g["tx_pkts"] != 2.0 || g["rx_pkts"] != nil {
		t.Errorf("arp group = %v, want tx only", g)
	}
	if !reflect.DeepEqual(a["services"], []any{map[string]any{"name": "_googlecast._tcp.local", "bytes": float64(len(q)), "pkts": 1.0}}) {
		t.Errorf("services = %v", a["services"])
	}
	if !reflect.DeepEqual(a["mdns_rr"], map[string]any{"PTR": 1.0}) {
		t.Errorf("mdns_rr = %v", a["mdns_rr"])
	}

	// another client of the same VAP: the VAP's tx, none of A's rx
	b := block(t, tb, "wl12", staB, t0)
	if got := typeCounts(b, "arp"); got[3] != 2 {
		t.Errorf("client B arp = %v: tx is the VAP's, the same for every client", got)
	}
	if got := typeCounts(b, "mdns"); got[1] != 0 {
		t.Errorf("client B mdns rx = %v, want 0", got)
	}
	if _, ok := b["mdns_rr"]; ok {
		t.Errorf("client B has mdns_rr without sending mDNS")
	}
	if _, ok := tb.Block("wl13", mac2s(staA), t0); ok {
		t.Errorf("Block on a VAP never inspected = ok")
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
		typ   string
		group string
		port  int
	}{
		{"ssdp", eth(bcast, staA, 0x0800, ip4(17, "192.168.0.50", "239.255.255.250", udp(40000, 1900, nil))), "ssdp", "239.255.255.250", 1900},
		{"ubnt discovery", eth(bcast, staA, 0x0800, ip4(17, "192.168.0.50", "233.89.188.1", udp(40000, 10001, nil))), "ubnt", "233.89.188.1", 10001},
		{"dhcp", eth(bcast, staA, 0x0800, ip4(17, "0.0.0.0", "255.255.255.255", udp(68, 67, nil))), "dhcp", "255.255.255.255", 67},
		{"subnet broadcast", eth(bcast, staA, 0x0800, ip4(17, "192.168.0.50", "192.168.0.255", udp(21027, 21027, nil))), "other", "192.168.0.255", 21027},
		{"ipv4 group", eth(bcast, staA, 0x0800, ip4(17, "192.168.0.50", "224.0.37.42", udp(2647, 2647, nil))), "stream", "224.0.37.42", 2647},
		{"igmp", eth(bcast, staA, 0x0800, ip4(2, "192.168.0.50", "224.0.0.22", igmpV3())), "igmp", "224.0.0.22", 0},
		{"ipv6 group", eth(bcast, staA, 0x86dd, ip6(17, "fe80::1", "ff12::8384", udp(21027, 21027, nil))), "stream", "ff12::8384", 21027},
		{"dhcpv6", eth(bcast, staA, 0x86dd, ip6(17, "fe80::1", "ff02::1:2", udp(546, 547, nil))), "dhcpv6", "ff02::1:2", 547},
		{"mdns v6", eth(bcast, staA, 0x86dd, ip6(17, "fe80::1", "ff02::fb", udp(5353, 5353, mdnsQuery("_hap._tcp.local", 12)))), "mdns", "ff02::fb", 5353},
		{"router solicitation", eth(bcast, staA, 0x86dd, ip6(58, "fe80::1", "ff02::2", []byte{133, 0, 0, 0, 0, 0, 0, 0})), "ipv6_nd", "ff02::2", 0},
		{"mld behind hop-by-hop", eth(bcast, staA, 0x86dd, ip6(0, "fe80::1", "ff02::16", hbh(mldV2(4, "ff02::fb")))), "mld", "ff02::16", 0},
		{"arp", eth(bcast, staA, 0x0806, make([]byte, 28)), "arp", "0.0.0.0", 0},
		{"tagged arp", eth(bcast, staA, 0x8100, append([]byte{0, 20, 0x08, 0x06}, make([]byte, 28)...)), "arp", "0.0.0.0", 0},
		{"other ethertype", eth(bcast, staA, 0x88cc, make([]byte, 20)), "other", "0.0.0.0", 0},
		{"truncated ipv4", eth(bcast, staA, 0x0800, []byte{0x45, 0}), "other", "0.0.0.0", 0},
	}
	for _, c := range cases {
		f, ok := Classify(c.frame, len(c.frame))
		if !ok {
			t.Errorf("%s: not classified", c.name)
			continue
		}
		if f.Type != c.typ || f.Group.String() != c.group || f.Port != c.port {
			t.Errorf("%s: got %s %s:%d, want %s %s:%d", c.name, f.Type, f.Group, f.Port, c.typ, c.group, c.port)
		}
	}
	if _, ok := Classify([]byte{1, 2, 3}, 3); ok {
		t.Errorf("a 3-byte frame classified")
	}
}

func TestMemberships(t *testing.T) {
	tb := NewTable()
	join := eth(bcast, staA, 0x0800, ip4(2, "192.168.0.50", "224.0.0.22", igmpV3(igmpRec(4, "239.1.2.3"), igmpRec(1, "232.1.1.1", "10.0.0.1"))))
	observe(tb, "wl02", join, false, t0)
	mjoin := eth(bcast, staA, 0x86dd, ip6(0, "fe80::1", "ff02::16", hbh(mldV2(4, "ff02::fb"))))
	observe(tb, "wl02", mjoin, false, t0.Add(10*time.Second))

	m := block(t, tb, "wl02", staA, t0.Add(30*time.Second))
	want := []any{
		map[string]any{"group_ip": "232.1.1.1", "age_ms": 30000.0},
		map[string]any{"group_ip": "239.1.2.3", "age_ms": 30000.0},
		map[string]any{"group_ip": "ff02::fb", "age_ms": 20000.0},
	}
	if !reflect.DeepEqual(m["memberships"], want) {
		t.Fatalf("memberships = %v, want %v", m["memberships"], want)
	}

	// a v2 leave and a v3 TO_IN{} drop a group; a refreshed report keeps
	// the first-seen age; groups not refreshed for 260 s age out
	leave := eth(bcast, staA, 0x0800, ip4(2, "192.168.0.50", "224.0.0.2", []byte{0x17, 0, 0, 0, 239, 1, 2, 3}))
	observe(tb, "wl02", leave, false, t0.Add(40*time.Second))
	observe(tb, "wl02", mjoin, false, t0.Add(200*time.Second))
	m = block(t, tb, "wl02", staA, t0.Add(300*time.Second))
	want = []any{map[string]any{"group_ip": "ff02::fb", "age_ms": 290000.0}}
	if !reflect.DeepEqual(m["memberships"], want) {
		t.Errorf("memberships after leave and ageing = %v, want %v", m["memberships"], want)
	}
	mleave := eth(bcast, staA, 0x86dd, ip6(0, "fe80::1", "ff02::16", hbh(mldV2(3, "ff02::fb"))))
	observe(tb, "wl02", mleave, false, t0.Add(301*time.Second))
	if m = block(t, tb, "wl02", staA, t0.Add(302*time.Second)); len(m["memberships"].([]any)) != 0 {
		t.Errorf("memberships after MLD TO_IN{} = %v, want none", m["memberships"])
	}
}

func TestRetainAndDrop(t *testing.T) {
	tb := NewTable()
	q := eth(mdnsMAC, staA, 0x0800, ip4(17, "192.168.0.50", "224.0.0.251", udp(5353, 5353, mdnsQuery("_hap._tcp.local", 12))))
	observe(tb, "wl12", q, false, t0)
	tb.Retain("wl12", []string{"02:00:00:00:00:A1"}) // still associated (any case)
	if got := typeCounts(block(t, tb, "wl12", staA, t0), "mdns"); got[1] != 1 {
		t.Fatalf("a client still associated lost its counters: %v", got)
	}
	tb.Retain("wl12", nil) // it left
	if got := typeCounts(block(t, tb, "wl12", staA, t0), "mdns"); got[1] != 0 {
		t.Errorf("a client that left kept its counters: %v", got)
	}
	tb.Drop("wl12")
	if _, ok := tb.Block("wl12", mac2s(staA), t0); ok {
		t.Errorf("a dropped VAP still reports")
	}
}

func TestGroupSourceIgnored(t *testing.T) {
	tb := NewTable()
	observe(tb, "wl12", eth(bcast, bcast, 0x0806, make([]byte, 28)), false, t0)
	if got := typeCounts(block(t, tb, "wl12", bcast, t0), "arp"); got != [4]float64{} {
		t.Errorf("a frame from a group source address was accounted to a client: %v", got)
	}
}

func TestParseMDNS(t *testing.T) {
	m := ParseMDNS(mdnsAnswer("_airplay._tcp.local"))
	if m == nil {
		t.Fatal("answer not parsed")
	}
	if !reflect.DeepEqual(m.RR, []string{"PTR", "SRV"}) {
		t.Errorf("RR = %v", m.RR)
	}
	// the PTR owner is a service; the SRV owner (instance "TV-1._airplay...")
	// is not
	if !reflect.DeepEqual(m.Services, []string{"_airplay._tcp.local"}) {
		t.Errorf("Services = %v", m.Services)
	}
	if ParseMDNS([]byte{1, 2, 3}) != nil {
		t.Errorf("a 3-byte message parsed")
	}
	// a compression loop must end
	loop := append(make([]byte, 12), 0xc0, 12, 0, 12, 0, 1)
	binary.BigEndian.PutUint16(loop[4:], 1)
	if m := ParseMDNS(loop); m == nil || len(m.RR) != 0 {
		t.Errorf("looping name: %+v", m)
	}
	// a message cut in its second record keeps the first
	full := mdnsAnswer("_raop._tcp.local")
	if m := ParseMDNS(full[:len(full)-3]); m == nil || !reflect.DeepEqual(m.RR, []string{"PTR"}) {
		t.Errorf("cut message: %+v", m)
	}
}

type fakeSource struct {
	mu     sync.Mutex
	frames [][]byte
	out    []bool
	closed bool
}

func (f *fakeSource) Recv(b []byte) (int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return 0, false, errors.New("closed")
	}
	if len(f.frames) == 0 {
		time.Sleep(time.Millisecond)
		return 0, false, ErrTimeout
	}
	fr, out := f.frames[0], f.out[0]
	f.frames, f.out = f.frames[1:], f.out[1:]
	return copy(b, fr), out, nil
}

func (f *fakeSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestRun(t *testing.T) {
	tb := NewTable()
	arp := eth(bcast, gw, 0x0806, make([]byte, 28))
	src := &fakeSource{frames: [][]byte{arp, arp}, out: []bool{true, false}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() { done <- Run(ctx, tb, "wl12", src, func() time.Time { return t0 }) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if b, ok := tb.Block("wl12", mac2s(gw), t0); ok {
			c := b["types"].(map[string]any)["arp"].(map[string]any)
			if c["tx_pkts"] == int64(1) && c["rx_pkts"] == int64(1) {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("frames not accounted")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Errorf("Run after cancel = %v", err)
	}
	if !src.closed {
		t.Errorf("source not closed")
	}
}
