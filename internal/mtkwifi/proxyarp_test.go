// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

func testARP(op uint16, ethDst, sha string, spa string, tha string, tpa string) []byte {
	b := make([]byte, 42)
	copy(b[0:], mac(ethDst))
	copy(b[6:], mac(sha))
	binary.BigEndian.PutUint16(b[12:], 0x0806)
	binary.BigEndian.PutUint16(b[14:], 1)
	binary.BigEndian.PutUint16(b[16:], 0x0800)
	b[18], b[19] = 6, 4
	binary.BigEndian.PutUint16(b[20:], op)
	copy(b[22:], mac(sha))
	copy(b[28:], net.ParseIP(spa).To4())
	copy(b[32:], mac(tha))
	copy(b[38:], net.ParseIP(tpa).To4())
	return b
}

// dhcpAck is an IPv4/UDP 67->68 BOOTREPLY with option 53 = 5.
func dhcpAck(chaddr, yiaddr string, msgType byte) []byte {
	b := make([]byte, 14+20+8+240+4)
	copy(b[0:], mac(chaddr))
	copy(b[6:], mac("00:11:22:33:44:55"))
	binary.BigEndian.PutUint16(b[12:], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(len(b)-14))
	ip[9] = 17
	udp := ip[20:]
	binary.BigEndian.PutUint16(udp[0:], 67)
	binary.BigEndian.PutUint16(udp[2:], 68)
	bootp := udp[8:]
	bootp[0], bootp[1], bootp[2] = 2, 1, 6
	copy(bootp[16:], net.ParseIP(yiaddr).To4())
	copy(bootp[28:], mac(chaddr))
	copy(bootp[236:], []byte{99, 130, 83, 99})
	copy(bootp[240:], []byte{53, 1, msgType, 255})
	return b
}

func TestParseARPAndReply(t *testing.T) {
	req := testARP(1, "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", "192.168.0.1", "00:00:00:00:00:00", "192.168.0.77")
	a, ok := parseARP(req)
	if !ok || a.op != 1 || !a.bcast || a.sha.String() != "00:11:22:33:44:55" || a.spa.String() != "192.168.0.1" || a.tpa.String() != "192.168.0.77" {
		t.Fatalf("parsed %+v %t", a, ok)
	}
	r := arpReply(mac("aa:bb:cc:dd:ee:01"), net.ParseIP("192.168.0.77"), a.sha, a.spa)
	got, ok := parseARP(r)
	if !ok || got.op != 2 || got.sha.String() != "aa:bb:cc:dd:ee:01" || got.spa.String() != "192.168.0.77" ||
		got.tha.String() != "00:11:22:33:44:55" || got.tpa.String() != "192.168.0.1" || net.HardwareAddr(r[0:6]).String() != "00:11:22:33:44:55" ||
		net.HardwareAddr(r[6:12]).String() != "aa:bb:cc:dd:ee:01" || len(r) < 60 {
		t.Errorf("reply %+v (%d bytes)", got, len(r))
	}
	// DAD probe (sender 0.0.0.0): the reply goes to 0.0.0.0
	dad := arpReply(mac("aa:bb:cc:dd:ee:01"), net.ParseIP("192.168.0.77"), a.sha, net.IPv4zero)
	if got, _ := parseARP(dad); !got.tpa.Equal(net.IPv4zero) {
		t.Errorf("DAD reply to %s", got.tpa)
	}
	g := garp(mac("aa:bb:cc:dd:ee:01"), net.ParseIP("192.168.0.77"))
	if got, ok := parseARP(g); !ok || got.op != 1 || !got.bcast || !got.spa.Equal(got.tpa) || got.sha.String() != "aa:bb:cc:dd:ee:01" {
		t.Errorf("GARP %+v", got)
	}
	if _, ok := parseARP(req[:30]); ok {
		t.Error("short frame parsed")
	}
}

func TestParseDHCPAck(t *testing.T) {
	m, ip, ok := parseDHCPAck(dhcpAck("aa:bb:cc:dd:ee:01", "192.168.0.77", 5))
	if !ok || m.String() != "aa:bb:cc:dd:ee:01" || ip.String() != "192.168.0.77" {
		t.Errorf("ack %s %s %t", m, ip, ok)
	}
	if _, _, ok := parseDHCPAck(dhcpAck("aa:bb:cc:dd:ee:01", "192.168.0.77", 2)); ok {
		t.Error("an OFFER learnt")
	}
}

// TestARPTable: a station's address is learnt from its own ARP (on its
// vif, while associated there) or its DHCP ACK; requests for it from
// others are answered on its behalf; it is forgotten when it leaves.
func TestARPTable(t *testing.T) {
	var tb arpTable
	sta := "aa:bb:cc:dd:ee:01"
	tb.setStations(map[string][]string{"ra1": {sta}})
	tb.learnFrame("ra1", testARP(1, "ff:ff:ff:ff:ff:ff", sta, "192.168.0.77", "00:00:00:00:00:00", "192.168.0.1"))
	// a frame of a station that is not associated there teaches nothing
	tb.learnFrame("ra1", testARP(2, "00:11:22:33:44:55", "aa:bb:cc:dd:ee:09", "192.168.0.99", "00:11:22:33:44:55", "192.168.0.1"))
	if _, ok := tb.lookup(net.ParseIP("192.168.0.99")); ok {
		t.Error("learnt a station not associated")
	}
	req := testARP(1, "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", "192.168.0.1", "00:00:00:00:00:00", "192.168.0.77")
	r := tb.answer(req)
	if r == nil {
		t.Fatal("no answer")
	}
	if got, _ := parseARP(r); got.sha.String() != sta || got.tha.String() != "00:11:22:33:44:55" {
		t.Errorf("answer %+v", got)
	}
	// the station asking about itself (DAD, its own GARP) and unicast
	// requests are not answered
	if tb.answer(testARP(1, "ff:ff:ff:ff:ff:ff", sta, "0.0.0.0", "00:00:00:00:00:00", "192.168.0.77")) != nil {
		t.Error("answered the station's own probe")
	}
	if tb.answer(testARP(1, sta, "00:11:22:33:44:55", "192.168.0.1", "00:00:00:00:00:00", "192.168.0.77")) != nil {
		t.Error("answered a unicast request")
	}
	tb.learnFrame("ra1", dhcpAck("aa:bb:cc:dd:ee:02", "192.168.0.78", 5))
	if _, ok := tb.lookup(net.ParseIP("192.168.0.78")); ok {
		t.Error("DHCP ACK learnt for a station not associated")
	}
	tb.setStations(map[string][]string{"ra1": {sta, "aa:bb:cc:dd:ee:02"}})
	tb.learnFrame("ra1", dhcpAck("aa:bb:cc:dd:ee:02", "192.168.0.78", 5))
	if m, ok := tb.lookup(net.ParseIP("192.168.0.78")); !ok || m.String() != "aa:bb:cc:dd:ee:02" {
		t.Error("DHCP ACK not learnt")
	}
	tb.setStations(map[string][]string{"ra1": {"aa:bb:cc:dd:ee:02"}})
	if _, ok := tb.lookup(net.ParseIP("192.168.0.77")); ok {
		t.Error("a station that left is still answered for")
	}
}

type fakeParp struct {
	vifs    map[string]parpVif
	healthy map[string]bool
	known   map[string][]string
	reqs    int
}

func (f *fakeParp) SetVifs(v map[string]parpVif)   { f.vifs = v }
func (f *fakeParp) Healthy(vif string) bool        { return f.healthy[vif] }
func (f *fakeParp) Request(*ProxyARPRequest)       { f.reqs++ }
func (f *fakeParp) Stations(map[string][]string)   {}
func (f *fakeParp) Neighbor(string) (net.IP, bool) { return nil, false }
func (f *fakeParp) Known(vif string) []string      { return f.known[vif] }

func parpHome() bcmwifi.Desired {
	d := home()
	d.SSIDs[0].ProxyARP = true // Example Network: ra0 and rai0
	return d
}

// TestProxyARPApply: the 2.4 GHz proxy ARP BSS gets the responder and its
// broadcast-request drop only while the responder is healthy; the 5 GHz
// BSS gets the driver flag only while the responder and the driver event
// listener are both healthy, and loses it when either dies; nothing goes
// out inside a restart's settle time; proxy ARP off in the config leaves
// it all off.
func TestProxyARPApply(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	fp := &fakeParp{healthy: map[string]bool{}, known: map[string][]string{"ra0": {"192.168.0.77"}, "rai0": {"192.168.0.78"}}}
	a.parp = fp
	events := false
	a.o.ProxyARP, a.o.ProxyARPDriver = true, true
	a.SetEventsHealthy(func() bool { return events })
	ctx := context.Background()
	p, _ := a.Plan(ctx, parpHome())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if fp.vifs["ra0"].Bridge != "bdg2" || !fp.vifs["ra0"].Learn || fp.vifs["rai0"].Learn || len(fp.vifs) != 2 {
		t.Errorf("responder vifs %+v", fp.vifs)
	}
	if c := cmdsFrom(f, 0, "iwpriv rai0 set hs_flag"); len(c) > 0 {
		t.Errorf("flag inside the settle time: %v", c)
	}
	*now += time.Minute
	n := len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "ebtables -A UDECO-PARP"); len(c) > 0 {
		t.Errorf("drop rule with the responder down: %v", c)
	}
	fp.healthy["ra0"], fp.healthy["rai0"] = true, true
	n = len(f.log)
	a.Tick(ctx)
	got := strings.Join(f.log[n:], "\n")
	if !strings.Contains(got, "ebtables -A UDECO-PARP -o ra0 -p ARP --arp-opcode Request --arp-ip-dst 192.168.0.77 -d ff:ff:ff:ff:ff:ff -j DROP") ||
		!strings.Contains(got, "ebtables -I FORWARD 1 -o ra0 -j UDECO-PARP") {
		t.Errorf("2.4 GHz drop:\n%s", got)
	}
	if strings.Contains(got, "hs_flag") {
		t.Errorf("driver flag without the event listener:\n%s", got)
	}
	events = true
	n = len(f.log)
	a.Tick(ctx)
	// hs_flag=3: bit0 (the driver learns its stations from their own ARP)
	// and bit1 (it drops the requests); bit1 alone (2) learns nothing
	if c := cmdsFrom(f, n, "iwpriv rai0 set hs_flag=3"); len(c) != 1 {
		t.Errorf("flag on: %v", f.log[n:])
	}
	// the listener dies: the flag goes at once (ProxyARPDown), not at the
	// next tick
	events = false
	n = len(f.log)
	a.ProxyARPDown(ctx)
	if c := cmdsFrom(f, n, "iwpriv rai0 set hs_flag=0"); len(c) != 1 {
		t.Errorf("flag off: %v", f.log[n:])
	}
	// the responder dies on 2.4 GHz: the drop goes
	fp.healthy["ra0"] = false
	n = len(f.log)
	a.Tick(ctx)
	if c := cmdsFrom(f, n, "ebtables -D FORWARD -o ra0 -j UDECO-PARP"); len(c) != 1 {
		t.Errorf("drop kept with the responder down: %v", f.log[n:])
	}
	// hand-back: everything off
	fp.healthy["ra0"], events = true, true
	a.Tick(ctx)
	n = len(f.log)
	a.mu.Lock()
	a.restoreBaseline(ctx)
	a.mu.Unlock()
	got = strings.Join(f.log[n:], "\n")
	if !strings.Contains(got, "iwpriv rai0 set hs_flag=0") || !strings.Contains(got, "ebtables -X UDECO-PARP") || len(fp.vifs) != 0 {
		t.Errorf("hand-back:\n%s\nvifs %v", got, fp.vifs)
	}

	// proxy_arp false: nothing at all
	g := newFakeDev(t)
	b, bnow := clocked(g)
	b.parp = &fakeParp{healthy: map[string]bool{"ra0": true, "rai0": true}}
	b.SetEventsHealthy(func() bool { return true })
	p, _ = b.Plan(ctx, parpHome())
	b.Apply(ctx, p)
	*bnow += time.Minute
	b.Tick(ctx)
	if c := cmdsFrom(g, 0, "ebtables -A UDECO-PARP"); len(c) > 0 || len(cmdsFrom(g, 0, "iwpriv rai0 set hs_flag=3")) > 0 {
		t.Errorf("proxy ARP off but applied")
	}
	if !strings.Contains(joined(p.Notes), "proxy ARP") {
		t.Errorf("not noted: %q", p.Notes)
	}
}

// By default (garage-final proxyarp: "do not enable the MT7663 driver flag
// by default") the 5 GHz BSS is served like the 2.4 GHz one: the agent
// learns and answers, an ebtables drop per learnt address; no hs_flag is
// ever sent. The chain's policy is RETURN: a frame no drop rule matches
// goes on to the guest isolation chains after it in FORWARD.
func TestProxyARPDefaultAgentSide(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	fp := &fakeParp{healthy: map[string]bool{"ra0": true, "rai0": true},
		known: map[string][]string{"ra0": {"192.168.0.77"}, "rai0": {"192.168.0.78"}}}
	a.parp = fp
	a.o.ProxyARP = true
	a.SetEventsHealthy(func() bool { return true })
	ctx := context.Background()
	p, _ := a.Plan(ctx, parpHome())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !fp.vifs["rai0"].Learn || !fp.vifs["ra0"].Learn {
		t.Errorf("responder vifs %+v, want both learnt by the agent", fp.vifs)
	}
	*now += time.Minute
	a.Tick(ctx)
	got := strings.Join(f.log, "\n")
	if strings.Contains(got, "hs_flag=2") || strings.Contains(got, "hs_flag=3") {
		t.Errorf("driver flag by default:\n%s", got)
	}
	if !strings.Contains(got, "ebtables -A UDECO-PARP -o rai0 -p ARP --arp-opcode Request --arp-ip-dst 192.168.0.78") {
		t.Errorf("no 5 GHz drop rule:\n%s", got)
	}
	if !strings.Contains(got, "ebtables -N UDECO-PARP -P RETURN") && !strings.Contains(got, "ebtables -P UDECO-PARP RETURN") {
		t.Errorf("chain without a RETURN policy:\n%s", got)
	}
}

// bpfRun is a classic BPF interpreter for the few opcodes learnFilter
// uses.
func bpfRun(prog []bpfIns, pkt []byte) uint32 {
	var acc, x uint32
	ld := func(off uint32, n int) (uint32, bool) {
		if int(off)+n > len(pkt) {
			return 0, false
		}
		switch n {
		case 1:
			return uint32(pkt[off]), true
		case 2:
			return uint32(binary.BigEndian.Uint16(pkt[off:])), true
		}
		return binary.BigEndian.Uint32(pkt[off:]), true
	}
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		var ok = true
		switch in.Code {
		case 0x28:
			acc, ok = ld(in.K, 2)
		case 0x30:
			acc, ok = ld(in.K, 1)
		case 0x48:
			acc, ok = ld(x+in.K, 2)
		case 0xb1:
			var v uint32
			v, ok = ld(in.K, 1)
			x = 4 * (v & 0xf)
		case 0x15:
			if acc == in.K {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x45:
			if acc&in.K != 0 {
				pc += int(in.Jt)
			} else {
				pc += int(in.Jf)
			}
		case 0x06:
			return in.K
		default:
			panic("opcode")
		}
		if !ok {
			return 0
		}
	}
	return 0
}

// TestLearnFilter: the learners' socket filter passes ARP and DHCP
// server-to-client datagrams only.
func TestLearnFilter(t *testing.T) {
	if bpfRun(learnFilter, testARP(1, "ff:ff:ff:ff:ff:ff", "00:11:22:33:44:55", "192.168.0.1", "00:00:00:00:00:00", "192.168.0.77")) == 0 {
		t.Error("ARP dropped")
	}
	if bpfRun(learnFilter, dhcpAck("aa:bb:cc:dd:ee:01", "192.168.0.77", 5)) == 0 {
		t.Error("DHCP ACK dropped")
	}
	other := dhcpAck("aa:bb:cc:dd:ee:01", "192.168.0.77", 5)
	binary.BigEndian.PutUint16(other[14+20:], 53) // DNS reply
	if bpfRun(learnFilter, other) != 0 {
		t.Error("DNS passed")
	}
	frag := dhcpAck("aa:bb:cc:dd:ee:01", "192.168.0.77", 5)
	frag[14+6] = 0x00
	frag[14+7] = 0x10 // fragment offset
	if bpfRun(learnFilter, frag) != 0 {
		t.Error("a fragment passed")
	}
	tcp := dhcpAck("aa:bb:cc:dd:ee:01", "192.168.0.77", 5)
	tcp[14+9] = 6
	if bpfRun(learnFilter, tcp) != 0 {
		t.Error("TCP passed")
	}
}
