// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
)

// Driver events: what the MediaTek drivers announce on their own, read by
// passive listeners (no ioctl, no iwpriv, no profile change), so station
// leaves reach the controller at once instead of at the next vap_table
// diff (events spec, docs/deco/features/garage-parity.md):
//
//   - rtnetlink (NETLINK_ROUTE, RTMGRP_LINK): RtmpOSWrielessEventSend puts
//     an IWEVCUSTOM iw_event in an RTM_NEWLINK's IFLA_WIRELESS. Flags 3
//     is MacTableInsertEntry, 4 MacTableDeleteEntry (both drivers, for
//     every MAC entry, so also stations that only authenticated), 0x953
//     the MT7663's WAPP events (sub 6 authorized, 7 MBO leave), 0x647 a
//     WAPP client leave, 0x93b the MT7663's proxy ARP request "to daemon"
//     (proxyarp.go).
//   - ECNT (netlink protocol 17, group 1): the Econet SDK's driver events
//     (wadt_send_drv_event, type 0x0A00): 1 a failed join (reason 14
//     wrong passphrase, 15 4-way handshake timeout), 4 a client's
//     deauth/disassoc, 0xe an AP-initiated leave. Asynchronous and lossy:
//     only logged.
//   - the kernel log (/dev/kmsg, its own reader position: the collector's
//     klogctl reads are untouched): the MT7603 always prints "Del Sta:%pM"
//     in MacTableDeleteEntry, a second source for 2.4 GHz leaves.
//
// A Delete becomes a Disconnected hapdmon.Event after leaveHold, unless
// its BSS (for a kernel log Del Sta, any 2.4 GHz BSS) had more than
// burstMax Deletes within burstWindow, counting the ones already released
// or dropped (a radio
// restart or a bulk kick: the reading diff handles those) or the radios
// were changing when it arrived (Options.Busy). staevents.go turns it into
// a sta_leave only for a station the controller was told is on that BSS,
// so a Delete of a station that never finished joining is no leave. A
// WAPP/MBO leave stands in for a Delete that did not come within
// fallbackHold.

// DrvKind is the kind of a driver event.
type DrvKind int

const (
	DrvInsert      DrvKind = iota + 1 // a MAC entry was created (authentication)
	DrvDelete                         // a MAC entry was deleted
	DrvAuthorized                     // the 4-way handshake completed (MT7663)
	DrvWappLeave                      // WAPP client leave
	DrvMboLeave                       // MBO station disassociation (MT7663)
	DrvProxyARP                       // an ARP request for a proxied station (MT7663, 0x93b)
	DrvFailure                        // ECNT: a failed join (Reason)
	DrvClientLeave                    // ECNT: the client left (Reason)
	DrvAPLeave                        // ECNT: the AP made the client leave
)

// AnyNG is the Ifname of a kernel log Del Sta: some 2.4 GHz BSS (the line
// names none).
const AnyNG = "ra?"

// DrvEvent is one driver event.
type DrvEvent struct {
	Kind   DrvKind
	Ifname string // the BSS netdev (ra0..ra3, rai0..rai3), or AnyNG
	MAC    string // the station, lower case
	BSSID  string // lower case, when the event has it
	Reason int    // ECNT failures and leaves
	ARP    *ProxyARPRequest
	At     time.Time
}

// ProxyARPRequest is the MT7663's 0x93b event: an ARP request the driver
// dropped because it targets one of its stations (RTMPCheckEtherType),
// for a responder to answer (wext_send_proxy_arp_event layout).
type ProxyARPRequest struct {
	Ifindex int  // the BSS netdev
	IPv6    bool // ip_type
	FromDS  bool // the request came from the wired side
	DAD     bool // duplicate address detection (sender IP 0)
	ReqMAC  net.HardwareAddr
	StaMAC  net.HardwareAddr
	ReqIP   net.IP
	StaIP   net.IP
}

const (
	iwevCustom   = 0x8C02
	rtmNewLink   = 16
	iflaIfname   = 3
	iflaWireless = 11
	ecntType     = 0x0A00
	ecntLen      = 0xe0
)

func macStr(b []byte) string { return net.HardwareAddr(b).String() }

// parseRTNL reads the IWEVCUSTOM driver events of one rtnetlink datagram.
func parseRTNL(b []byte) []DrvEvent {
	le := binary.LittleEndian
	var out []DrvEvent
	for len(b) >= 16 {
		n := int(le.Uint32(b[0:]))
		if n < 16 || n > len(b) {
			break
		}
		msg := b[:n]
		b = b[min(len(b), (n+3)&^3):]
		if le.Uint16(msg[4:]) != rtmNewLink || len(msg) < 32 {
			continue
		}
		var ifname string
		var wireless []byte
		attrs := msg[32:]
		for len(attrs) >= 4 {
			l := int(le.Uint16(attrs[0:]))
			if l < 4 || l > len(attrs) {
				break
			}
			switch le.Uint16(attrs[2:]) {
			case iflaIfname:
				ifname = string(bytes.TrimRight(attrs[4:l], "\x00"))
			case iflaWireless:
				wireless = attrs[4:l]
			}
			attrs = attrs[min(len(attrs), (l+3)&^3):]
		}
		for len(wireless) >= 8 {
			l := int(le.Uint16(wireless[0:]))
			if l < 4 || l > len(wireless) {
				break
			}
			ev := wireless[:l]
			wireless = wireless[l:]
			if le.Uint16(ev[2:]) != iwevCustom || l < 8 {
				continue
			}
			dlen, flags := int(le.Uint16(ev[4:])), le.Uint16(ev[6:])
			if 8+dlen > l {
				continue
			}
			if e, ok := customEvent(ifname, flags, ev[8:8+dlen]); ok {
				out = append(out, e)
			}
		}
	}
	return out
}

func customEvent(ifname string, flags uint16, d []byte) (DrvEvent, bool) {
	e := DrvEvent{Ifname: ifname}
	switch {
	case (flags == 3 || flags == 4) && len(d) == 6:
		e.Kind, e.MAC = DrvInsert, macStr(d)
		if flags == 4 {
			e.Kind = DrvDelete
		}
	case flags == 0x647 && len(d) >= 14 && d[1] == 9:
		e.Kind, e.MAC = DrvWappLeave, macStr(d[8:14])
	case flags == 0x953 && len(d) >= 18 && d[5] == 6:
		e.Kind, e.MAC, e.BSSID = DrvAuthorized, macStr(d[6:12]), macStr(d[12:18])
	case flags == 0x953 && len(d) >= 12 && d[5] == 7:
		e.Kind, e.MAC = DrvMboLeave, macStr(d[6:12])
	case flags == 0x93b && len(d) >= 27:
		r := &ProxyARPRequest{Ifindex: int(binary.LittleEndian.Uint32(d[0:])), IPv6: d[4] != 0, FromDS: d[5] != 0,
			DAD: d[6] != 0, ReqMAC: append(net.HardwareAddr{}, d[7:13]...), StaMAC: append(net.HardwareAddr{}, d[13:19]...),
			ReqIP: net.IP(append([]byte{}, d[19:23]...)), StaIP: net.IP(append([]byte{}, d[23:27]...))}
		e.Kind, e.MAC, e.ARP = DrvProxyARP, r.StaMAC.String(), r
	default:
		return e, false
	}
	return e, true
}

// parseECNT reads the driver events of one ECNT netlink datagram.
func parseECNT(b []byte) []DrvEvent {
	le := binary.LittleEndian
	var out []DrvEvent
	for len(b) >= 16 {
		n := int(le.Uint32(b[0:]))
		if n < 16 || n > len(b) {
			break
		}
		msg := b[:n]
		b = b[min(len(b), (n+3)&^3):]
		if le.Uint16(msg[4:]) != ecntType || len(msg) < 16+ecntLen {
			continue
		}
		p := msg[16:]
		e := DrvEvent{MAC: macStr(p[4:10]), BSSID: macStr(p[10:16])}
		sub := le.Uint32(p[0:])
		if sub != 0xe {
			e.Reason = int(le.Uint32(p[16:]))
			e.Ifname = string(bytes.TrimRight(p[20:36], "\x00"))
		}
		switch sub {
		case 1:
			e.Kind = DrvFailure
		case 4:
			e.Kind = DrvClientLeave
		case 0xe:
			e.Kind = DrvAPLeave
		default:
			continue
		}
		out = append(out, e)
	}
	return out
}

var delStaRE = regexp.MustCompile(`;Del Sta:([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})`)

// parseKmsg reads a /dev/kmsg record ("pri,seq,ts,flags;text"): the
// MT7603's "Del Sta:<mac>, Chip:..." is a 2.4 GHz Delete.
func parseKmsg(rec string) (DrvEvent, bool) {
	m := delStaRE.FindStringSubmatch(rec)
	if m == nil {
		return DrvEvent{}, false
	}
	return DrvEvent{Kind: DrvDelete, Ifname: AnyNG, MAC: strings.ToLower(m[1])}, true
}

// --------------------------------------------------------------- monitor

const (
	leaveHold    = time.Second     // a Delete waits this long for a burst to show
	burstWindow  = time.Second     // more than burstMax Deletes of one BSS within it are a burst
	burstMax     = 3               //
	fallbackHold = 2 * time.Second // a WAPP/MBO leave waits this long for its Delete
	dedupWindow  = 5 * time.Second // a second source's Delete of the same station is the same leave
	eventsMax    = 256             // released leaves kept until Take
)

// EventsOptions configure an Events monitor.
type EventsOptions struct {
	Logf func(string, ...any)
	// Busy reports that the radios are being changed or settling (the
	// applier's RestartGate refusing a read): events arriving meanwhile
	// are the restart's own and are dropped.
	Busy func() bool
	// Notify is called (from the monitor's goroutine) when a leave is
	// released, so the agent reads the unit soon.
	Notify func()
	// ProxyARP gets the MT7663's proxy ARP requests (proxyarp.go).
	ProxyARP func(*ProxyARPRequest)
	// Down is called (from the listener's goroutine) when the rtnetlink
	// listener closes: nothing answers the 0x93b requests until it is
	// back (Applier.ProxyARPDown).
	Down func()
	// NG2 follows the kernel log for the MT7603's Del Sta lines.
	NG2 bool
	Now func() time.Time
	// test hooks: the sources (nil = the real sockets, drvevents_linux.go)
	openRTNL, openECNT, openKmsg func() (packetSource, error)
}

// packetSource is one datagram (or kernel log record) per Read.
type packetSource interface {
	Read([]byte) (int, error)
	Close() error
}

// Events follows the drivers' events (see above).
type Events struct {
	o  EventsOptions
	mu sync.Mutex
	// staged Deletes and fallbacks waiting for leaveHold/fallbackHold
	staged []DrvEvent
	// dels: every Delete staged lately (released or dropped too), for the
	// burst count: the staged ones alone lose a burst's head once it is
	// dropped, and its tail then looked like single leaves
	dels []DrvEvent
	// reported: when each station's leave was last released or staged
	reported map[string]time.Time
	out      []hapdmon.Event
	dropped  int
	rtnlUp   bool
	failSeen map[string]time.Time // ECNT failures logged, per station
}

// NewEvents returns a monitor; nothing is opened until Run.
func NewEvents(o EventsOptions) *Events {
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Busy == nil {
		o.Busy = func() bool { return false }
	}
	return &Events{o: o, reported: map[string]time.Time{}, failSeen: map[string]time.Time{}}
}

// Take returns the released leaves (oldest first) and how many were
// dropped since the last Take.
func (m *Events) Take() ([]hapdmon.Event, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out, d := m.out, m.dropped
	m.out, m.dropped = nil, 0
	return out, d
}

// Healthy reports that the rtnetlink listener is open (proxy ARP's
// driver flag depends on it).
func (m *Events) Healthy() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rtnlUp
}

func (m *Events) setUp(up bool) {
	m.mu.Lock()
	m.rtnlUp = up
	m.mu.Unlock()
	if !up && m.o.Down != nil {
		m.o.Down()
	}
}

// handle takes one event as it arrives.
func (m *Events) handle(e DrvEvent) {
	if e.Kind == DrvProxyARP {
		if m.o.ProxyARP != nil && e.ARP != nil {
			m.o.ProxyARP(e.ARP)
		}
		return
	}
	now := m.o.Now()
	e.At = now
	switch e.Kind {
	case DrvFailure:
		m.logFailure(e, now)
		return
	case DrvDelete, DrvMboLeave, DrvWappLeave:
	default:
		return
	}
	if m.o.Busy() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if e.Kind == DrvDelete {
		if t, ok := m.reported[e.MAC]; ok && now.Sub(t) < dedupWindow {
			// the other source's report of the same leave; it may stand
			// in for a staged fallback
			m.dropFallback(e.MAC)
			return
		}
		m.reported[e.MAC] = now
		m.dropFallback(e.MAC)
		m.dels = append(m.dels, e)
	}
	m.staged = append(m.staged, e)
}

func (m *Events) dropFallback(mac string) {
	kept := m.staged[:0]
	for _, s := range m.staged {
		if s.Kind == DrvDelete || s.MAC != mac {
			kept = append(kept, s)
		}
	}
	m.staged = kept
}

// flush releases the staged events whose hold is over.
func (m *Events) flush() {
	now := m.o.Now()
	m.mu.Lock()
	var kept []DrvEvent
	released := false
	for _, s := range m.staged {
		hold := leaveHold
		if s.Kind != DrvDelete {
			hold = fallbackHold
		}
		if now.Sub(s.At) < hold {
			kept = append(kept, s)
			continue
		}
		if s.Kind == DrvDelete && m.burst(s) {
			continue
		}
		if s.Kind != DrvDelete {
			if t, ok := m.reported[s.MAC]; ok && t.After(s.At.Add(-dedupWindow)) {
				continue
			}
			m.reported[s.MAC] = now
		}
		if len(m.out) >= eventsMax {
			m.out, m.dropped = m.out[1:], m.dropped+1
		}
		m.out = append(m.out, hapdmon.Event{Vif: s.Ifname, MAC: s.MAC, Kind: hapdmon.Disconnected, At: s.At})
		released = true
	}
	m.staged = kept
	keepDels := m.dels[:0]
	for _, d := range m.dels {
		if now.Sub(d.At) <= leaveHold+burstWindow+time.Second {
			keepDels = append(keepDels, d)
		}
	}
	m.dels = keepDels
	for mac, t := range m.reported {
		if now.Sub(t) > time.Minute {
			delete(m.reported, mac)
		}
	}
	m.mu.Unlock()
	if released && m.o.Notify != nil {
		m.o.Notify()
	}
}

// burst: s's BSS had more than burstMax Deletes within burstWindow of it
// (every Delete seen lately, released or not). The kernel log's Del Sta
// (AnyNG: some 2.4 GHz BSS) counts with every 2.4 GHz BSS, and they with
// it: a 2.4 GHz reset shows on either source.
func (m *Events) burst(s DrvEvent) bool {
	n := 0
	for _, x := range m.dels {
		if sameBurstBSS(x.Ifname, s.Ifname) && absDur(x.At.Sub(s.At)) <= burstWindow {
			n++
		}
	}
	return n > burstMax
}

func sameBurstBSS(a, b string) bool {
	ng := func(s string) bool { return s == AnyNG || strings.HasPrefix(s, "ra") && !strings.HasPrefix(s, "rai") }
	if a == AnyNG || b == AnyNG {
		return ng(a) && ng(b)
	}
	return a == b
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

var failReasons = map[int]string{14: "wrong passphrase (MIC failure)", 15: "4-way handshake timeout"}

// logFailure logs a failed join (ECNT), once a minute per station.
func (m *Events) logFailure(e DrvEvent, now time.Time) {
	m.mu.Lock()
	t, seen := m.failSeen[e.MAC]
	if seen && now.Sub(t) < time.Minute {
		m.mu.Unlock()
		return
	}
	m.failSeen[e.MAC] = now
	for mac, t := range m.failSeen {
		if now.Sub(t) > time.Minute {
			delete(m.failSeen, mac)
		}
	}
	m.mu.Unlock()
	why := failReasons[e.Reason]
	if why == "" {
		why = "reason " + strconv.Itoa(e.Reason)
	}
	m.o.Logf("client %s failed to join %s (%s): %s", e.MAC, e.Ifname, e.BSSID, why)
}

// Run follows the sources until ctx ends, reopening each with a back-off.
func (m *Events) Run(ctx context.Context) {
	var wg sync.WaitGroup
	follow := func(name string, open func() (packetSource, error), parse func([]byte) []DrvEvent, up func(bool)) {
		defer wg.Done()
		wait := time.Second
		for ctx.Err() == nil {
			src, err := open()
			if err != nil {
				m.o.Logf("driver events: %s: %v (retrying in %s)", name, err, wait)
				if !sleepCtx(ctx, wait) {
					return
				}
				wait = min(2*wait, time.Minute)
				continue
			}
			wait = time.Second
			if up != nil {
				up(true)
			}
			stop := context.AfterFunc(ctx, func() { src.Close() })
			buf := make([]byte, 64<<10)
			for {
				n, err := src.Read(buf)
				if err != nil {
					break
				}
				for _, e := range parse(buf[:n]) {
					m.handle(e)
				}
			}
			stop()
			src.Close()
			if up != nil {
				up(false)
			}
			if ctx.Err() == nil {
				m.o.Logf("driver events: %s closed: reopening", name)
				if !sleepCtx(ctx, wait) {
					return
				}
			}
		}
	}
	rtnl, ecnt, kmsg := m.o.openRTNL, m.o.openECNT, m.o.openKmsg
	if rtnl == nil {
		rtnl, ecnt, kmsg = openRTNLSocket, openECNTSocket, openKmsgFile
	}
	wg.Add(2)
	go follow("rtnetlink", rtnl, parseRTNL, m.setUp)
	go follow("ecnt", ecnt, parseECNT, nil)
	if m.o.NG2 {
		wg.Add(1)
		go follow("kernel log", kmsg, func(b []byte) []DrvEvent {
			if e, ok := parseKmsg(string(b)); ok {
				return []DrvEvent{e}
			}
			return nil
		}, nil)
	}
	t := time.NewTicker(250 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case <-t.C:
			m.flush()
		}
	}
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
