// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// --- DNS message builder (uncompressed unless a test adds pointers) ---

type tq struct {
	name     string
	typ      uint16
	qu       bool
	response bool
}

type trr struct {
	name  string
	typ   uint16
	ttl   uint32
	rdata []byte
}

func encName(s string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(s, "."), ".") {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func srvData(port uint16, target string) []byte {
	b := []byte{0, 0, 0, 0}
	b = binary.BigEndian.AppendUint16(b, port)
	return append(b, encName(target)...)
}

func dnsMsg(response bool, qs []tq, an, ar []trr) []byte {
	b := make([]byte, 12)
	if response {
		binary.BigEndian.PutUint16(b[2:], 0x8400)
	}
	binary.BigEndian.PutUint16(b[4:], uint16(len(qs)))
	binary.BigEndian.PutUint16(b[6:], uint16(len(an)))
	binary.BigEndian.PutUint16(b[10:], uint16(len(ar)))
	for _, q := range qs {
		b = append(b, encName(q.name)...)
		b = binary.BigEndian.AppendUint16(b, q.typ)
		c := uint16(1)
		if q.qu {
			c |= classQU
		}
		b = binary.BigEndian.AppendUint16(b, c)
	}
	for _, sec := range [][]trr{an, ar} {
		for _, r := range sec {
			b = append(b, encName(r.name)...)
			b = binary.BigEndian.AppendUint16(b, r.typ)
			b = binary.BigEndian.AppendUint16(b, 0x8001)
			b = binary.BigEndian.AppendUint32(b, r.ttl)
			b = binary.BigEndian.AppendUint16(b, uint16(len(r.rdata)))
			b = append(b, r.rdata...)
		}
	}
	return b
}

func names(t *testing.T, b []byte) (qs []string, rrs []string) {
	t.Helper()
	m, err := parseMessage(b)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	for _, q := range m.qs {
		qs = append(qs, q.n.key())
	}
	for _, sec := range [][]record{m.an, m.ns, m.ar} {
		for _, r := range sec {
			rrs = append(rrs, r.n.key())
		}
	}
	return qs, rrs
}

var (
	staMAC  = [6]byte{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}
	tvMAC   = [6]byte{0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0x01}
	unitMAC = [6]byte{0x50, 0x91, 0xe3, 0x00, 0x00, 0x01}
)

func frame4(src [6]byte, ip string, payload []byte) []byte {
	p := packet{src: src, ipSrc: netip.MustParseAddr(ip), ttl: 255}
	f, ok := p.build(payload)
	if !ok {
		panic("build")
	}
	return f
}

func frame6(src [6]byte, ip string, payload []byte) []byte {
	p := packet{src: src, v6: true, ipSrc: netip.MustParseAddr(ip), ttl: 255}
	f, ok := p.build(payload)
	if !ok {
		panic("build")
	}
	return f
}

func payloadOf(t *testing.T, f []byte) []byte {
	t.Helper()
	p, ok := parseFrame(f)
	if !ok {
		t.Fatalf("not an mDNS frame")
	}
	return p.payload
}

// --- config ---

// cfgText is what Network 10.6/11.1 writes for two WLANs on a unit with
// bridges br0 (untagged) and br0.3: WLAN "home" (VAPs ra1, rai1, untagged)
// in custom mode taking AirPlay and Chromecast from VLANs 3 and 30, and
// WLAN "iot" (ra2, VLAN 3) in auto mode.
const cfgText = `mdns_sd.status=enabled
mdns_sd.proxy.1.status=enabled
mdns_sd.proxy.1.dst.1.devname=br0
mdns_sd.proxy.1.src.1.devname=br0.3
mdns_sd.proxy.1.src.2.devname=br0.30
mdns_sd.filter.1.vlan=1
mdns_sd.filter.1.policy=deny
mdns_sd.filter.1.dst.1.devname=ra1
mdns_sd.filter.1.dst.2.devname=rai1
mdns_sd.filter.1.service.1.name=_airplay._tcp.local
mdns_sd.filter.1.service.2.name=_googlecast._tcp.local
mdns_sd.filter.2.vlan=3
mdns_sd.filter.2.policy=deny
mdns_sd.filter.2.dst.1.devname=ra1
mdns_sd.filter.2.dst.2.devname=rai1
mdns_sd.filter.2.service.1.name=_airplay._tcp.local
mdns_sd.filter.2.service.2.name=_googlecast._tcp.local
mdns_sd.filter.3.vlan=30
mdns_sd.filter.3.policy=deny
mdns_sd.filter.3.dst.1.devname=ra1
mdns_sd.filter.3.dst.2.devname=rai1
mdns_sd.filter.3.service.1.name=_airplay._tcp.local
mdns_sd.filter.4.vlan=3
mdns_sd.filter.4.policy=deny
mdns_sd.filter.4.dst.1.devname=ra2
mdns_sd.filter.4.service.1.name=_amzn-wplay._tcp.local
mdns_sd.filter.4.service.2.name=_amazonecho-remote._tcp
mdns_sd.filter.4.service.3.name=_matterc._udp
`

func TestParseConfig(t *testing.T) {
	c, notes := ParseConfig(translate.ParseCfg(cfgText))
	if len(notes) != 0 {
		t.Errorf("notes: %v", notes)
	}
	if !c.Enabled || c.APMode {
		t.Errorf("enabled/ap_mode = %t/%t", c.Enabled, c.APMode)
	}
	if want := []Proxy{{Dst: "br0", Srcs: []string{"br0.3", "br0.30"}}}; !reflect.DeepEqual(c.Proxies, want) {
		t.Errorf("proxies = %+v", c.Proxies)
	}
	if len(c.Filters) != 4 {
		t.Fatalf("filters = %+v", c.Filters)
	}
	f := c.Filters[3]
	if f.VLAN != 3 || f.Allow || !reflect.DeepEqual(f.VAPs, []string{"ra2"}) ||
		!reflect.DeepEqual(f.Services, []string{"_amzn-wplay._tcp", "_amazonecho-remote._tcp", "_matterc._udp"}) {
		t.Errorf("filter 4 = %+v", f)
	}

	// off, bad parts, fail-closed policy
	if c, _ := ParseConfig(map[string]string{"mdns_sd.status": "disabled", "mdns_sd.filter.1.vlan": "1"}); c.Enabled || len(c.Filters) > 0 {
		t.Errorf("disabled section parsed: %+v", c)
	}
	c, notes = ParseConfig(map[string]string{
		"mdns_sd.status": "enabled", "mdns_sd.ap_mode": "enabled",
		"mdns_sd.proxy.1.status": "enabled", "mdns_sd.proxy.1.dst.1.devname": "br0", "mdns_sd.proxy.1.src.1.devname": "br0",
		"mdns_sd.proxy.2.status": "disabled", "mdns_sd.proxy.2.dst.1.devname": "br0", "mdns_sd.proxy.2.src.1.devname": "br0.5",
		"mdns_sd.proxy.3.status": "enabled", "mdns_sd.proxy.3.dst.1.devname": "br0;reboot", "mdns_sd.proxy.3.src.1.devname": "br0.5",
		"mdns_sd.filter.1.vlan": "1", "mdns_sd.filter.1.policy": "permit", "mdns_sd.filter.1.dst.1.devname": "ra0",
		"mdns_sd.filter.1.service.1.name": "_ok._tcp.local", "mdns_sd.filter.1.service.2.name": "not-a-service",
		"mdns_sd.filter.2.vlan": "5000", "mdns_sd.filter.2.policy": "allow", "mdns_sd.filter.2.dst.1.devname": "ra0",
	})
	if !c.APMode || len(c.Proxies) != 0 {
		t.Errorf("proxies = %+v (src == dst, disabled, bad name all dropped)", c.Proxies)
	}
	if len(c.Filters) != 1 || c.Filters[0].Allow || !reflect.DeepEqual(c.Filters[0].Services, []string{"_ok._tcp"}) {
		t.Errorf("filters = %+v (unknown policy is deny; bad service and bad VLAN dropped)", c.Filters)
	}
	if len(notes) < 4 {
		t.Errorf("notes = %v", notes)
	}
}

func TestNormServiceAndBridgeVLAN(t *testing.T) {
	for in, want := range map[string]string{"_AirPlay._tcp.local.": "_airplay._tcp", "_matterc._udp": "_matterc._udp",
		"airplay._tcp": "", "": "", "_a.._tcp": "", "_x\x00._tcp": ""} {
		if got := NormService(in); got != want {
			t.Errorf("NormService(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]int{"br0": 1, "br0.3": 3, "br0.30": 30, "br0.1": 1, "br0.0": -1, "br0.5000": -1, "eth0": -1, "br0.03": -1} {
		v, ok := BridgeVLAN(in)
		if (want < 0 && ok) || (want >= 0 && (!ok || v != want)) {
			t.Errorf("BridgeVLAN(%q) = %d, %t", in, v, ok)
		}
	}
}

// --- service filter ---

func TestPolicyService(t *testing.T) {
	p := NewPolicy(Filter{Services: []string{"_airplay._tcp", "_http._tcp", "_matterc._udp"}})
	for n, want := range map[string]bool{
		"_airplay._tcp.local": true, "Living Room._airplay._tcp.local": true, "_printer._sub._http._tcp.local": true,
		"_matterc._udp.local": true, "_raop._tcp.local": false, "_services._dns-sd._udp.local": false,
		"x_airplay._tcp.local": false, "_AIRPLAY._TCP.LOCAL": true,
	} {
		if got := p.ServiceAllowed(n); got != want {
			t.Errorf("deny-but %q = %t", n, got)
		}
	}
	a := NewPolicy(Filter{Allow: true, Services: []string{"_ssh._tcp"}})
	if a.ServiceAllowed("box._ssh._tcp.local") || !a.ServiceAllowed("_airplay._tcp.local") {
		t.Errorf("allow-but policy wrong")
	}
	if !NewPolicy(Filter{Allow: true}).All() || NewPolicy(Filter{}).All() {
		t.Errorf("All() wrong")
	}
}

func TestFilterQuery(t *testing.T) {
	p := NewPolicy(Filter{Services: []string{"_airplay._tcp"}})
	q := dnsMsg(false, []tq{{name: "_airplay._tcp.local", typ: typePTR, qu: true}, {name: "_ssh._tcp.local", typ: typePTR}},
		[]trr{{name: "_ssh._tcp.local", typ: typePTR, ttl: 4500, rdata: encName("box._ssh._tcp.local")}}, nil)
	out, ok := filterMessage(q, p, nil, true)
	if !ok {
		t.Fatal("query dropped")
	}
	qs, rrs := names(t, out)
	if !reflect.DeepEqual(qs, []string{"_airplay._tcp.local"}) || len(rrs) != 0 {
		t.Errorf("kept %v %v", qs, rrs)
	}
	m, _ := parseMessage(out)
	if m.qs[0].class&classQU != 0 {
		t.Errorf("QU bit kept")
	}
	// the original is untouched
	if m0, _ := parseMessage(q); m0.qs[0].class&classQU == 0 {
		t.Errorf("input modified")
	}
	// only denied questions: nothing to send
	if _, ok := filterMessage(dnsMsg(false, []tq{{name: "_ssh._tcp.local", typ: typePTR}}, nil, nil), p, nil, true); ok {
		t.Errorf("denied query forwarded")
	}
	// allow-all: same bytes, or a copy with only the QU bits cleared
	all := NewPolicy(Filter{Allow: true})
	if out, ok := filterMessage(q, all, nil, false); !ok || &out[0] != &q[0] {
		t.Errorf("allow-all copied the message")
	}
	out, _ = filterMessage(q, all, nil, true)
	if len(out) != len(q) || bytes.Equal(out, q) {
		t.Errorf("allow-all with clearQU: %x", out)
	}
	if m, _ := parseMessage(out); m.qs[0].class != 1 || len(m.qs) != 2 {
		t.Errorf("allow-all with clearQU: %+v", m.qs)
	}
}

func TestFilterResponse(t *testing.T) {
	p := NewPolicy(Filter{Services: []string{"_airplay._tcp"}})
	r := dnsMsg(true, nil, []trr{
		{name: "_airplay._tcp.local", typ: typePTR, ttl: 4500, rdata: encName("TV._airplay._tcp.local")},
		{name: "_ssh._tcp.local", typ: typePTR, ttl: 4500, rdata: encName("box._ssh._tcp.local")},
		{name: "_services._dns-sd._udp.local", typ: typePTR, ttl: 4500, rdata: encName("_airplay._tcp.local")},
	}, []trr{
		{name: "TV._airplay._tcp.local", typ: typeSRV, ttl: 120, rdata: srvData(7000, "tv.local")},
		{name: "TV._airplay._tcp.local", typ: 16, ttl: 4500, rdata: []byte{3, 'a', '=', '1'}},
		{name: "tv.local", typ: typeA, ttl: 120, rdata: []byte{192, 168, 3, 20}},
		{name: "box._ssh._tcp.local", typ: typeSRV, ttl: 120, rdata: srvData(22, "box.local")},
		{name: "box.local", typ: typeA, ttl: 120, rdata: []byte{192, 168, 3, 21}},
		{name: "20.3.168.192.in-addr.arpa", typ: typePTR, ttl: 120, rdata: encName("tv.local")},
		{name: "tv.local", typ: 15, ttl: 120, rdata: append([]byte{0, 10}, encName("tv.local")...)}, // MX: unmovable
	})
	out, ok := filterMessage(r, p, nil, false)
	if !ok {
		t.Fatal("dropped")
	}
	_, rrs := names(t, out)
	want := []string{"_airplay._tcp.local", "tv._airplay._tcp.local", "tv._airplay._tcp.local", "tv.local"}
	if !reflect.DeepEqual(rrs, want) {
		t.Errorf("kept %v, want %v", rrs, want)
	}
	// the rebuilt SRV still points at tv.local
	m, _ := parseMessage(out)
	if m.ar[0].typ != typeSRV || m.ar[0].target.key() != "tv.local" || binary.BigEndian.Uint16(m.ar[0].srvHead[4:]) != 7000 {
		t.Errorf("SRV = %+v", m.ar[0])
	}
	// DNS-SD enumeration: kept only for an allowed type when dns-sd is allowed
	p2 := NewPolicy(Filter{Services: []string{"_airplay._tcp", "_dns-sd._udp"}})
	out, _ = filterMessage(r, p2, nil, false)
	if _, rrs := names(t, out); !strings.Contains(strings.Join(rrs, " "), "_services._dns-sd._udp.local") {
		t.Errorf("enumeration of an allowed type dropped: %v", rrs)
	}
}

func TestHostCache(t *testing.T) {
	p := NewPolicy(Filter{Services: []string{"_airplay._tcp"}})
	c := newHostCache()
	now := time.Unix(1000, 0)
	aq := dnsMsg(false, []tq{{name: "tv.local", typ: typeA}}, nil, nil)
	if _, ok := filterMessage(aq, p, c.view(3, now), true); ok {
		t.Fatal("address question for an unknown host forwarded")
	}
	ann, _ := parseMessage(dnsMsg(true, nil, []trr{{name: "TV._airplay._tcp.local", typ: typeSRV, ttl: 120, rdata: srvData(7000, "tv.local")}}, nil))
	c.learn(3, ann, now)
	if _, ok := filterMessage(aq, p, c.view(3, now), true); !ok {
		t.Error("address question for an AirPlay host dropped")
	}
	if _, ok := filterMessage(aq, p, c.view(30, now), true); ok {
		t.Error("host learnt on VLAN 3 counted on VLAN 30")
	}
	if _, ok := filterMessage(aq, p, c.view(3, now.Add(121*time.Second)), true); ok {
		t.Error("expired host still allowed")
	}
	bye, _ := parseMessage(dnsMsg(true, nil, []trr{{name: "TV._airplay._tcp.local", typ: typeSRV, ttl: 0, rdata: srvData(7000, "tv.local")}}, nil))
	c.learn(3, bye, now)
	if _, ok := filterMessage(aq, p, c.view(3, now), true); ok {
		t.Error("goodbye did not forget the host")
	}
}

func TestParseMessageRejects(t *testing.T) {
	loop := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 12, 0, 1, 0, 1}
	fwd := []byte{0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xc0, 14, 0, 1, 0, 1}
	trunc := dnsMsg(true, nil, []trr{{name: "a.local", typ: typeA, ttl: 1, rdata: []byte{1, 2, 3, 4}}}, nil)
	many := make([]byte, 12)
	binary.BigEndian.PutUint16(many[6:], 300)
	for name, b := range map[string][]byte{"self pointer": loop, "forward pointer": fwd, "truncated": trunc[:len(trunc)-2],
		"short": {1, 2, 3}, "too many records": many} {
		if _, err := parseMessage(b); err == nil {
			t.Errorf("%s: parsed", name)
		}
	}
	// a compressed message parses
	c := dnsMsg(true, nil, []trr{{name: "_airplay._tcp.local", typ: typePTR, ttl: 1, rdata: append([]byte{2, 'T', 'V'}, 0xc0, 12)}}, nil)
	m, err := parseMessage(c)
	if err != nil || m.an[0].target.key() != "tv._airplay._tcp.local" {
		t.Errorf("compressed: %v %+v", err, m)
	}
}

// --- frames and BPF ---

func TestFrames(t *testing.T) {
	q := dnsMsg(false, []tq{{name: "_airplay._tcp.local", typ: typePTR}}, nil, nil)
	for _, f := range [][]byte{frame4(staMAC, "192.168.0.50", q), frame6(staMAC, "fe80::1", q)} {
		p, ok := parseFrame(f)
		if !ok || !bytes.Equal(p.payload, q) || p.src != staMAC || p.ttl != 255 {
			t.Errorf("round trip: %t %+v", ok, p)
		}
	}
	f := frame4(staMAC, "192.168.0.50", q)
	bad := append([]byte(nil), f...)
	bad[len(bad)-1] ^= 0xff // UDP checksum no longer matches
	if _, ok := parseFrame(bad); ok {
		t.Error("bad checksum accepted")
	}
	frag := append([]byte(nil), f...)
	frag[14+6] |= 0x20 // MF
	binary.BigEndian.PutUint16(frag[14+10:], 0)
	binary.BigEndian.PutUint16(frag[14+10:], csum(0, frag[14:34]))
	if _, ok := parseFrame(frag); ok {
		t.Error("fragment accepted")
	}
	grp := append([]byte(nil), f...)
	grp[6] |= 1
	if _, ok := parseFrame(grp); ok {
		t.Error("group source MAC accepted")
	}
	big := make([]byte, 1500)
	if _, ok := (packet{ipSrc: netip.MustParseAddr("192.168.0.50")}).build(big); ok {
		t.Error("oversized frame built")
	}
}

func TestBPF(t *testing.T) {
	q := dnsMsg(false, []tq{{name: "_airplay._tcp.local", typ: typePTR}}, nil, nil)
	v4, v6 := frame4(staMAC, "192.168.0.50", q), frame6(staMAC, "fe80::1", q)
	other := append([]byte(nil), v4...)
	other[14+16+3] = 0xfc // 224.0.0.252 (LLMNR)
	opts := append([]byte(nil), v4...)
	opts[14] = 0x46
	frag := append([]byte(nil), v4...)
	frag[14+7] = 1
	plain, _ := assemble(filterProgram(0))
	tagged, _ := assemble(filterProgram(30))
	cases := []struct {
		name  string
		prog  [][4]uint32
		f     []byte
		vlan  int
		match bool
	}{
		{"v4 untagged", plain, v4, -1, true},
		{"v6 untagged", plain, v6, -1, true},
		{"v4 tagged on a plain port", plain, v4, 30, false},
		{"v4 VLAN 30 on its virtual port", tagged, v4, 30, true},
		{"v6 VLAN 30 on its virtual port", tagged, v6, 30, true},
		{"VLAN 31 on VLAN 30's port", tagged, v4, 31, false},
		{"untagged on a virtual port", tagged, v4, -1, false},
		{"another group", plain, other, -1, false},
		{"IP options", plain, opts, -1, false},
		{"fragment", plain, frag, -1, false},
		{"runt", plain, v4[:20], -1, false},
	}
	for _, c := range cases {
		if got := runBPF(c.prog, c.f, c.vlan) != 0; got != c.match {
			t.Errorf("%s: match = %t", c.name, got)
		}
	}
	if got := tag(v4, 30); binary.BigEndian.Uint16(got[12:]) != 0x8100 || binary.BigEndian.Uint16(got[14:]) != 30 || !bytes.Equal(got[16:], v4[12:]) {
		t.Errorf("tag: %x", got[:20])
	}
}
