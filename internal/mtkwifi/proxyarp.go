// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"sort"
	"strings"
	"sync"

	"slices"

	"github.com/antoniocosta/unifi-openwrt/internal/stasnoop"
)

// Proxy ARP (the controller's per-WLAN proxy_arp; agent config proxy_arp,
// on by default, turns it off). A U6 answers ARP requests for its
// stations itself, so the broadcast requests never go out on the air.
//
// 5 GHz (MT7663), by default served like 2.4 GHz below (garage-final
// proxyarp: "do not enable the MT7663 driver flag by default"). With
// Options.ProxyARPDriver (config proxy_arp_driver) the driver does it
// instead (iwpriv rai<N> set hs_flag=3: bit0 makes it learn its stations
// from their own ARP, bit1 drops the broadcast ARP requests for them and
// hands each one to a daemon as an IWEVCUSTOM 0x93b event, drvevents.go;
// bit1 alone learns only from a DHCP ACK sent while it is on, so the
// stations that joined before were black-holed). Nothing answers unless a
// responder does: the flag is set only while the agent's rtnetlink
// listener (the events' only way in) and the responder's sending socket
// are both healthy, and cleared at once when either dies, at startup, and
// at the hand-back.
//
// 2.4 GHz (MT7603), and 5 GHz by default: the responder learns each
// station's address from its own ARP and its DHCP ACK (an AF_PACKET socket
// on the BSS netdev with learnFilter), answers the broadcast requests the
// bridge delivers for those addresses, and an ebtables rule per learnt
// address (UDECO-PARP, policy RETURN: a frame no rule drops goes on to
// the guest isolation chains) keeps them off the air. A request for an address
// it has not learnt still goes out (fail open), as the Linux bridge's own
// proxy ARP does; the rules exist only while the responder's sockets are
// healthy.
//
// IPv6 neighbour solicitations are not proxied.

const chainParp = "UDECO-PARP"

// parpVif is one proxy ARP BSS: its bridge, and whether the responder
// learns its stations' addresses (the MT7603) or the driver does.
type parpVif struct {
	Bridge string
	Learn  bool
}

// parpResponder answers ARP requests for the stations (proxyarp_linux.go).
type parpResponder interface {
	// SetVifs sets the proxy ARP BSSes (empty: stop everything)
	SetVifs(map[string]parpVif)
	// Healthy: the sockets vif depends on are open
	Healthy(vif string) bool
	// Request answers an MT7663 0x93b event
	Request(*ProxyARPRequest)
	// Stations sets the associated stations per BSS netdev (a station's
	// address is learnt and answered for only while it is associated)
	Stations(map[string][]string)
	// Neighbor is a learnt station's address
	Neighbor(mac string) (net.IP, bool)
	// Known is the addresses answered for on vif, sorted
	Known(vif string) []string
}

// SetEventsHealthy gives the applier the driver event listener's health
// (mtkwifi.Events.Healthy): the 5 GHz proxy ARP flag depends on it.
func (a *Applier) SetEventsHealthy(f func() bool) {
	a.mu.Lock()
	a.eventsOK = f
	a.mu.Unlock()
}

// ProxyARPDown re-checks proxy ARP at once (the event listener or a
// responder socket died): the 5 GHz flag goes off outside a restart's
// settle time.
func (a *Applier) ProxyARPDown(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.live != nil {
		a.syncProxyARP(ctx)
	}
}

// ProxyARPRequest answers the MT7663's 0x93b event (EventsOptions.ProxyARP).
func (a *Applier) ProxyARPRequest(r *ProxyARPRequest) {
	if a.parp != nil {
		a.parp.Request(r)
	}
}

// ProxyARPStations gives the responder the associated stations, by BSS
// netdev (each reading).
func (a *Applier) ProxyARPStations(m map[string][]string) {
	if a.parp != nil {
		a.parp.Stations(m)
	}
}

// Neighbor is a station's address as the proxy ARP responder learnt it.
func (a *Applier) Neighbor(mac string) (net.IP, bool) {
	if a.parp == nil {
		return nil, false
	}
	return a.parp.Neighbor(strings.ToLower(mac))
}

// parpVifs are the proxy ARP BSSes of a.live.
func (a *Applier) parpVifs() map[string]parpVif {
	out := map[string]parpVif{}
	if !a.o.ProxyARP || a.o.DryRun || a.live == nil {
		return out
	}
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		if !rp.On {
			continue
		}
		for i, b := range rp.BSS {
			if !b.ProxyARP {
				continue
			}
			br := a.o.Bridge
			if b.VLAN > 0 {
				br = vlanBridge(b.VLAN)
			}
			out[a.ifaceOf(rd, rp, i)] = parpVif{Bridge: br, Learn: !rd.HSFlag || !a.o.ProxyARPDriver}
		}
	}
	return out
}

// syncProxyARP brings the responder, the 2.4 GHz drop rules and the
// 5 GHz driver flags to a.live (a.mu held).
func (a *Applier) syncProxyARP(ctx context.Context) {
	vifs := a.parpVifs()
	if a.parp != nil {
		a.parp.SetVifs(vifs)
	}
	names := make([]string, 0, len(vifs))
	for v := range vifs {
		names = append(names, v)
	}
	sort.Strings(names)
	var jumps, rules []string
	for _, v := range names {
		if vifs[v].Learn && a.parp != nil && a.parp.Healthy(v) {
			jumps = append(jumps, v)
			for _, ip := range a.parp.Known(v) {
				rules = append(rules, v+" "+ip)
			}
		}
	}
	a.syncParpEb(ctx, jumps, rules)
	if a.settling() {
		return // the flags are live iwpriv: after the settle time
	}
	events := a.eventsOK != nil && a.eventsOK()
	if a.parpFlag == nil {
		a.parpFlag = map[string]bool{}
	}
	for _, rd := range a.o.Layout {
		if !rd.HSFlag {
			continue
		}
		for _, ifc := range rd.Ifaces {
			v, ok := vifs[ifc]
			want := ok && !v.Learn && events && a.parp != nil && a.parp.Healthy(ifc)
			cur, known := a.parpFlag[ifc]
			if known && cur == want || !known && !want && !a.o.ProxyARP || !a.isUp(ifc) {
				continue
			}
			if err := a.run(ctx, "iwpriv", ifc, "set", "hs_flag="+map[bool]string{true: "3", false: "0"}[want]); err != nil {
				a.o.Logf("mtkwifi: %s: proxy ARP flag: %v", ifc, err)
				continue
			}
			a.parpFlag[ifc] = want
		}
	}
}

// parpRestarted: band's radio restarts; its flags are re-sent after the
// settle time.
func (a *Applier) parpRestarted(rd RadioDef) {
	for _, ifc := range rd.Ifaces {
		delete(a.parpFlag, ifc)
	}
}

// syncParpEb keeps the 2.4 GHz drop rules: per jump vif, its broadcast
// ARP requests for each learnt address (rules: "vif ip").
func (a *Applier) syncParpEb(ctx context.Context, jumps, rules []string) {
	state := strings.Join(jumps, " ") + "|" + strings.Join(rules, ",")
	if state == a.parpEb {
		return
	}
	if len(jumps) == 0 {
		if len(a.parpJumps) > 0 || a.parpEb != "" {
			a.removeParpEb(ctx)
		}
		return
	}
	if !a.chainExists(ctx, chainParp) {
		if err := a.eb(ctx, "-N", chainParp, "-P", "RETURN"); err != nil {
			a.o.Logf("mtkwifi: proxy ARP: %v", err)
			return
		}
	} else if err := a.eb(ctx, "-P", chainParp, "RETURN"); err != nil {
		// an older build's chain had the default ACCEPT policy, which let
		// every frame skip the guest isolation chains after the jump
		a.o.Logf("mtkwifi: proxy ARP: %v", err)
		return
	}
	if err := a.eb(ctx, "-F", chainParp); err != nil {
		a.o.Logf("mtkwifi: proxy ARP: %v", err)
		return
	}
	for _, r := range rules {
		vif, ip, _ := strings.Cut(r, " ")
		if err := a.eb(ctx, "-A", chainParp, "-o", vif, "-p", "ARP", "--arp-opcode", "Request", "--arp-ip-dst", ip,
			"-d", "ff:ff:ff:ff:ff:ff", "-j", "DROP"); err != nil {
			a.o.Logf("mtkwifi: proxy ARP: %v", err)
		}
	}
	for _, v := range jumps {
		if !slices.Contains(a.parpJumps, v) {
			_ = a.eb(ctx, "-D", "FORWARD", "-o", v, "-j", chainParp) // never twice
			if err := a.eb(ctx, "-I", "FORWARD", "1", "-o", v, "-j", chainParp); err != nil {
				a.o.Logf("mtkwifi: proxy ARP: %v", err)
			}
		}
	}
	for _, v := range a.parpJumps {
		if !slices.Contains(jumps, v) {
			_ = a.eb(ctx, "-D", "FORWARD", "-o", v, "-j", chainParp)
		}
	}
	a.parpJumps, a.parpEb = jumps, state
}

func (a *Applier) removeParpEb(ctx context.Context) {
	for _, v := range a.parpJumps {
		_ = a.eb(ctx, "-D", "FORWARD", "-o", v, "-j", chainParp)
	}
	_ = a.eb(ctx, "-F", chainParp)
	_ = a.eb(ctx, "-X", chainParp)
	a.parpJumps, a.parpEb = nil, ""
}

// parpOff turns proxy ARP off (hand-back), before the radios restart.
// Inside a settle time no hs_flag is sent (live iwpriv): the restart that
// follows clears the flag anyway.
func (a *Applier) parpOff(ctx context.Context) {
	for ifc, on := range a.parpFlag {
		if on && !a.settling() {
			_ = a.run(ctx, "iwpriv", ifc, "set", "hs_flag=0")
		}
	}
	a.parpFlag = nil
	if a.parp != nil {
		a.parp.SetVifs(map[string]parpVif{})
	}
	if len(a.parpJumps) > 0 || a.parpEb != "" {
		a.removeParpEb(ctx)
	}
}

// ------------------------------------------------------------ frames

var bcastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

type arpPkt struct {
	op       uint16
	bcast    bool
	src      net.HardwareAddr // Ethernet source
	sha, tha net.HardwareAddr
	spa, tpa net.IP
}

// parseARP reads an untagged Ethernet IPv4 ARP frame of any operation, the
// addresses as bytes (the responder's own reader: stasnoop.Parse reads
// requests and replies only, into the text of a connection event).
func parseARP(b []byte) (arpPkt, bool) {
	if len(b) < 42 || binary.BigEndian.Uint16(b[12:]) != 0x0806 || binary.BigEndian.Uint16(b[14:]) != 1 ||
		binary.BigEndian.Uint16(b[16:]) != 0x0800 || b[18] != 6 || b[19] != 4 {
		return arpPkt{}, false
	}
	return arpPkt{op: binary.BigEndian.Uint16(b[20:]), bcast: bytes.Equal(b[0:6], bcastMAC),
		src: net.HardwareAddr(slices.Clone(b[6:12])),
		sha: net.HardwareAddr(slices.Clone(b[22:28])), spa: net.IP(slices.Clone(b[28:32])),
		tha: net.HardwareAddr(slices.Clone(b[32:38])), tpa: net.IP(slices.Clone(b[38:42]))}, true
}

// arpReply is sha's reply (spa is at sha) to tha's request from tpa. The
// frame is stasnoop.ARPFrame's, as the Deco agent's.
func arpReply(sha net.HardwareAddr, spa net.IP, tha net.HardwareAddr, tpa net.IP) []byte {
	if tpa == nil {
		tpa = net.IPv4zero
	}
	return stasnoop.ARPFrame(tha, sha, 2, spa, tha, tpa)
}

// garp is a gratuitous ARP request: ip is at mac (stasnoop.GARPFrame; not
// stasnoop.GARP, which refuses a group address that AnnounceStation takes).
func garp(mac net.HardwareAddr, ip net.IP) []byte { return stasnoop.GARPFrame(mac, ip) }

// parseDHCPAck reads an untagged IPv4 UDP 67->68 BOOTREPLY DHCPACK: the
// client's hardware address and its address.
func parseDHCPAck(b []byte) (net.HardwareAddr, net.IP, bool) {
	if len(b) < 14+20 || binary.BigEndian.Uint16(b[12:]) != 0x0800 {
		return nil, nil, false
	}
	ip := b[14:]
	ihl := int(ip[0]&0xf) * 4
	if ip[0]>>4 != 4 || ihl < 20 || ip[9] != 17 || binary.BigEndian.Uint16(ip[6:])&0x1fff != 0 || len(ip) < ihl+8+240 {
		return nil, nil, false
	}
	udp := ip[ihl:]
	if binary.BigEndian.Uint16(udp[0:]) != 67 || binary.BigEndian.Uint16(udp[2:]) != 68 {
		return nil, nil, false
	}
	bp := udp[8:]
	if bp[0] != 2 || bp[1] != 1 || bp[2] != 6 || !bytes.Equal(bp[236:240], []byte{99, 130, 83, 99}) {
		return nil, nil, false
	}
	ack := false
	for o := bp[240:]; len(o) > 0; {
		switch o[0] {
		case 0:
			o = o[1:]
			continue
		case 255:
			o = nil
			continue
		}
		if len(o) < 2 || len(o) < 2+int(o[1]) {
			break
		}
		if o[0] == 53 && o[1] == 1 {
			ack = o[2] == 5
		}
		o = o[2+int(o[1]):]
	}
	yi := net.IP(slices.Clone(bp[16:20]))
	if !ack || yi.Equal(net.IPv4zero) {
		return nil, nil, false
	}
	return net.HardwareAddr(slices.Clone(bp[28:34])), yi, true
}

// bpfIns is one classic BPF instruction (syscall.SockFilter's layout).
type bpfIns struct {
	Code   uint16
	Jt, Jf uint8
	K      uint32
}

// learnFilter passes ARP and unfragmented IPv4 UDP 67->68 (DHCP server to
// client) frames.
var learnFilter = []bpfIns{
	{0x28, 0, 0, 12},      // 0: ldh [12]
	{0x15, 10, 0, 0x0806}, // 1: ARP -> accept
	{0x15, 0, 10, 0x0800}, // 2: not IPv4 -> drop
	{0x30, 0, 0, 23},      // 3: ldb [23] protocol
	{0x15, 0, 8, 17},      // 4: not UDP -> drop
	{0x28, 0, 0, 20},      // 5: ldh [20] fragment
	{0x45, 6, 0, 0x1fff},  // 6: a fragment -> drop
	{0xb1, 0, 0, 14},      // 7: ldxb 4*([14]&0xf)
	{0x48, 0, 0, 14},      // 8: ldh [x+14] source port
	{0x15, 0, 3, 67},      // 9: not 67 -> drop
	{0x48, 0, 0, 16},      // 10: ldh [x+16] destination port
	{0x15, 0, 1, 68},      // 11: not 68 -> drop
	{0x06, 0, 0, 0xffff},  // 12: accept
	{0x06, 0, 0, 0},       // 13: drop
}

// ------------------------------------------------------------ the table

// arpTable is the learnt addresses of the associated stations.
type arpTable struct {
	mu    sync.Mutex
	sta   map[string]string // MAC -> the BSS netdev it is associated to
	byIP  map[string]string // ip -> MAC
	byMAC map[string]string // MAC -> ip
}

func (t *arpTable) setStations(m map[string][]string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sta = map[string]string{}
	for vif, macs := range m {
		for _, s := range macs {
			t.sta[strings.ToLower(s)] = vif
		}
	}
	for mac, ip := range t.byMAC {
		if _, ok := t.sta[mac]; !ok {
			delete(t.byMAC, mac)
			delete(t.byIP, ip)
		}
	}
}

func (t *arpTable) set(mac, ip string) {
	if t.byIP == nil {
		t.byIP, t.byMAC = map[string]string{}, map[string]string{}
	}
	if old, ok := t.byMAC[mac]; ok {
		delete(t.byIP, old)
	}
	if other, ok := t.byIP[ip]; ok {
		delete(t.byMAC, other)
	}
	t.byIP[ip], t.byMAC[mac] = mac, ip
}

// learnFrame learns from a frame seen on vif: a station's own ARP (sender
// and Ethernet source the same associated station) or its DHCP ACK.
func (t *arpTable) learnFrame(vif string, f []byte) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if a, ok := parseARP(f); ok {
		m := a.sha.String()
		if t.sta[m] == vif && bytes.Equal(a.src, a.sha) && !a.spa.Equal(net.IPv4zero) {
			t.set(m, a.spa.String())
		}
		return
	}
	if m, ip, ok := parseDHCPAck(f); ok && t.sta[m.String()] == vif {
		t.set(m.String(), ip.String())
	}
}

func (t *arpTable) lookup(ip net.IP) (net.HardwareAddr, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	m, ok := t.byIP[ip.String()]
	if !ok {
		return nil, false
	}
	hw, _ := net.ParseMAC(m)
	return hw, true
}

func (t *arpTable) neighbor(mac string) (net.IP, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	ip, ok := t.byMAC[mac]
	return net.ParseIP(ip).To4(), ok
}

func (t *arpTable) known(vif string) []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []string
	for mac, ip := range t.byMAC {
		if t.sta[mac] == vif {
			out = append(out, ip)
		}
	}
	sort.Strings(out)
	return out
}

// answer is the reply to a broadcast ARP request for a learnt station
// whose BSS ok accepts (nil: all), or nil: never to the station itself.
func (t *arpTable) answer(req []byte) []byte { return t.answerFor(req, nil) }

func (t *arpTable) answerFor(req []byte, ok func(vif string) bool) []byte {
	a, good := parseARP(req)
	if !good || a.op != 1 || !a.bcast || a.spa.Equal(a.tpa) {
		return nil
	}
	t.mu.Lock()
	m, have := t.byIP[a.tpa.String()]
	vif := t.sta[m]
	t.mu.Unlock()
	if !have || m == a.sha.String() || ok != nil && !ok(vif) {
		return nil
	}
	hw, _ := net.ParseMAC(m)
	return arpReply(hw, a.tpa, a.sha, a.spa)
}
