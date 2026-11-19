// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"fmt"
	"hash/fnv"
	"sort"
	"strings"
	"sync"
	"time"
)

// The forwarding engine: pure logic, no sockets (service.go feeds it).
//
// Every port of the bridges involved is tapped on its own (a Wi-Fi vif, an
// Ethernet port, a VLAN device, or the uplink for 802.1Q frames of a VLAN
// that has no bridge on the unit), and frames are sent on ports, never into
// a bridge device: a frame sent into a bridge would flood every port,
// guest vifs included, past the guest ebtables chains (FORWARD) that guard
// them. Guest vifs are never tapped and never sent to.
//
// For a frame from port In (VLAN V):
//
//  1. Own VLAN: every intercepted vif on V other than In gets the frame
//     through its filter for V. An intercepted vif is one whose filter for
//     its own VLAN restricts something; ebtables (ebtables.go) drops native
//     mDNS to it, so the engine is its only source of mDNS.
//  2. Queries from a vif whose WLAN takes services from VLAN S (a route) go
//     to S: questions (and known answers) through the route's filter, QU
//     bits cleared so the answers come back as multicast, sent on every
//     port of S (only its vifs in AP mode); an intercepted vif of S gets it
//     through its own filter as well.
//  3. Responses from VLAN S go to every vif with a route from S, through
//     that route's filter. In AP mode only responses from a vif count.
//
// Loop freedom: only vif-originated queries are sent to wired ports, and
// wire-originated traffic only goes to vifs, so two bridges (two agents, or
// an agent and a real UAP) never hand a frame back and forth; frames from
// the unit's own MACs are dropped, and a duplicate of a message seen in the
// last DedupWindow is not forwarded again.

// Port is one tapped interface.
type Port struct {
	Name string // interface to bind and send on
	VID  int    // > 0: a virtual port: the 802.1Q frames of VLAN VID on Name
	VLAN int    // controller VLAN (1 = untagged)
	Vif  bool   // a Wi-Fi VAP
}

// Key names the port (Name, or Name@VID for a virtual port).
func (p Port) Key() string {
	if p.VID > 0 {
		return fmt.Sprintf("%s@%d", p.Name, p.VID)
	}
	return p.Name
}

// Route: the WLAN on vif takes services from SrcVLAN through Policy.
type Route struct {
	Vif     string // port key
	SrcVLAN int
	Policy  *Policy
}

// Plan is what the engine forwards.
type Plan struct {
	Ports  []Port
	Own    map[string]*Policy // intercepted vif (port key) -> its own VLAN's filter
	Routes []Route
	APMode bool
	OwnMAC [][6]byte // the unit's MACs: frames from them are never forwarded
}

// Sig is a stable text form of the plan (to tell a change).
func (p Plan) Sig() string {
	var b strings.Builder
	ports := append([]Port(nil), p.Ports...)
	sort.Slice(ports, func(i, j int) bool { return ports[i].Key() < ports[j].Key() })
	for _, x := range ports {
		fmt.Fprintf(&b, "port %s vlan %d vif %t\n", x.Key(), x.VLAN, x.Vif)
	}
	var own []string
	for v, pol := range p.Own {
		own = append(own, fmt.Sprintf("own %s %s", v, pol.sig()))
	}
	sort.Strings(own)
	for _, o := range own {
		b.WriteString(o + "\n")
	}
	var rs []string
	for _, r := range p.Routes {
		rs = append(rs, fmt.Sprintf("route %s from %d %s", r.Vif, r.SrcVLAN, r.Policy.sig()))
	}
	sort.Strings(rs)
	for _, r := range rs {
		b.WriteString(r + "\n")
	}
	var macs []string
	for _, m := range p.OwnMAC {
		macs = append(macs, fmt.Sprintf("%x", m))
	}
	sort.Strings(macs)
	fmt.Fprintf(&b, "ap %t macs %s\n", p.APMode, strings.Join(macs, ","))
	return b.String()
}

func (p *Policy) sig() string {
	var s []string
	for k := range p.Services {
		s = append(s, k)
	}
	sort.Strings(s)
	return fmt.Sprintf("allow=%t[%s]", p.Allow, strings.Join(s, " "))
}

// Out is a frame to send on a port.
type Out struct {
	Port  string // port key
	Frame []byte
}

// Rates bounds the engine's work.
type Rates struct {
	PortPPS, PortBurst float64 // frames taken from one port
	MACPPS, MACBurst   float64 // frames taken from one source MAC
	OutPPS, OutBurst   float64 // frames sent, all ports
}

// DefaultRates are generous for mDNS (a busy home LAN sees tens of frames a
// second) and small next to what a flood would cost.
var DefaultRates = Rates{PortPPS: 100, PortBurst: 200, MACPPS: 20, MACBurst: 60, OutPPS: 400, OutBurst: 800}

// DedupWindow: a message seen again within it is not forwarded again (mDNS
// repeats queries and announcements at 1 s or more).
const DedupWindow = 500 * time.Millisecond

const (
	maxMACBuckets = 1024
	maxDedup      = 4096
)

// Counters are the engine's totals.
type Counters struct {
	In, Out, Bad, Own, Dup, Limited, Filtered uint64
}

// Engine decides what to send for each frame. It is safe for concurrent use.
type Engine struct {
	mu     sync.Mutex
	plan   Plan
	ports  map[string]Port
	own    map[[6]byte]bool
	rates  Rates
	portTB map[string]*bucket
	macTB  map[[6]byte]*bucket
	outTB  *bucket
	seen   map[uint64]time.Time
	hosts  *hostCache
	c      Counters
}

// NewEngine returns an engine with no plan (it forwards nothing).
func NewEngine(r Rates) *Engine {
	e := &Engine{rates: r, portTB: map[string]*bucket{}, macTB: map[[6]byte]*bucket{},
		seen: map[uint64]time.Time{}, hosts: newHostCache(), outTB: newBucket(r.OutPPS, r.OutBurst, time.Time{})}
	e.SetPlan(Plan{})
	return e
}

// SetPlan replaces the plan.
func (e *Engine) SetPlan(p Plan) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.plan = p
	e.ports = map[string]Port{}
	for _, x := range p.Ports {
		e.ports[x.Key()] = x
	}
	e.own = map[[6]byte]bool{}
	for _, m := range p.OwnMAC {
		e.own[m] = true
	}
	for k := range e.portTB {
		if _, ok := e.ports[k]; !ok {
			delete(e.portTB, k)
		}
	}
}

// Counters returns the totals.
func (e *Engine) Counters() Counters {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.c
}

// Handle takes a frame received on port in (not one the port sent) and
// returns what to send.
func (e *Engine) Handle(in string, frame []byte, now time.Time) []Out {
	e.mu.Lock()
	defer e.mu.Unlock()
	src, ok := e.ports[in]
	if !ok {
		return nil
	}
	e.c.In++
	pk, ok := parseFrame(frame)
	if !ok {
		e.c.Bad++
		return nil
	}
	if e.own[pk.src] {
		e.c.Own++
		return nil
	}
	m, err := parseMessage(pk.payload)
	if err != nil {
		e.c.Bad++
		return nil
	}
	if !e.take(in, pk.src, now) {
		e.c.Limited++
		return nil
	}
	if m.response() {
		e.hosts.learn(src.VLAN, m, now)
	}
	if e.dup(pk, now) {
		e.c.Dup++
		return nil
	}
	var outs []Out
	send := func(port string, payload []byte, unchanged bool) {
		if !e.outTB.take(now) {
			e.c.Limited++
			return
		}
		f := frame
		if !unchanged {
			var ok bool
			if f, ok = pk.build(payload); !ok {
				e.c.Filtered++
				return
			}
		}
		outs = append(outs, Out{Port: port, Frame: f})
		e.c.Out++
	}
	// 1. own VLAN
	for _, k := range sortedKeys(e.plan.Own) {
		p := e.ports[k]
		if k == in || p.VLAN != src.VLAN {
			continue
		}
		if b, ok := filterMessage(pk.payload, e.plan.Own[k], e.hosts.view(src.VLAN, now), false); ok {
			send(k, b, sameBytes(b, pk.payload))
		} else {
			e.c.Filtered++
		}
	}
	// 2. queries from a vif with routes
	if src.Vif && !m.response() {
		for _, r := range e.plan.Routes {
			if r.Vif != in || r.SrcVLAN == src.VLAN {
				continue
			}
			b, ok := filterMessage(pk.payload, r.Policy, e.hosts.view(r.SrcVLAN, now), true)
			if !ok {
				e.c.Filtered++
				continue
			}
			for _, p := range e.plan.Ports {
				if p.VLAN != r.SrcVLAN || (e.plan.APMode && !p.Vif) {
					continue
				}
				pb := b
				if own := e.plan.Own[p.Key()]; own != nil {
					// an intercepted vif of that VLAN: its own filter too
					if pb, ok = filterMessage(b, own, e.hosts.view(r.SrcVLAN, now), false); !ok {
						e.c.Filtered++
						continue
					}
				}
				send(p.Key(), pb, sameBytes(pb, pk.payload))
			}
		}
	}
	// 3. responses into the vifs that take services from this VLAN
	if m.response() && (src.Vif || !e.plan.APMode) {
		for _, r := range e.plan.Routes {
			if r.SrcVLAN != src.VLAN || r.Vif == in {
				continue
			}
			if p, ok := e.ports[r.Vif]; !ok || p.VLAN == src.VLAN {
				continue
			}
			if b, ok := filterMessage(pk.payload, r.Policy, e.hosts.view(src.VLAN, now), false); ok {
				send(r.Vif, b, sameBytes(b, pk.payload))
			} else {
				e.c.Filtered++
			}
		}
	}
	return dedupOuts(outs)
}

// dedupOuts keeps the first frame per port (two routes of one vif from one
// VLAN, which the controller does not send, would otherwise double it).
func dedupOuts(outs []Out) []Out {
	seen := map[string]bool{}
	var keep []Out
	for _, o := range outs {
		if !seen[o.Port] {
			seen[o.Port] = true
			keep = append(keep, o)
		}
	}
	return keep
}

func sameBytes(a, b []byte) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

func sortedKeys[V any](m map[string]V) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// take applies the port and source-MAC limits.
func (e *Engine) take(port string, mac [6]byte, now time.Time) bool {
	pb := e.portTB[port]
	if pb == nil {
		pb = newBucket(e.rates.PortPPS, e.rates.PortBurst, now)
		e.portTB[port] = pb
	}
	mb := e.macTB[mac]
	if mb == nil {
		if len(e.macTB) >= maxMACBuckets {
			for k, b := range e.macTB { // forget the full (idle) ones
				if b.full(now) {
					delete(e.macTB, k)
				}
			}
			if len(e.macTB) >= maxMACBuckets {
				return false // fail closed under a MAC flood
			}
		}
		mb = newBucket(e.rates.MACPPS, e.rates.MACBurst, now)
		e.macTB[mac] = mb
	}
	return pb.take(now) && mb.take(now)
}

// dup reports a message seen in the last DedupWindow (and records it).
func (e *Engine) dup(pk packet, now time.Time) bool {
	h := fnv.New64a()
	h.Write(pk.ipSrc.AsSlice())
	h.Write(pk.payload)
	k := h.Sum64()
	if t, ok := e.seen[k]; ok && now.Sub(t) < DedupWindow {
		return true
	}
	if len(e.seen) >= maxDedup {
		for x, t := range e.seen {
			if now.Sub(t) >= DedupWindow {
				delete(e.seen, x)
			}
		}
		if len(e.seen) >= maxDedup {
			return true // fail closed: a flood of distinct messages
		}
	}
	e.seen[k] = now
	return false
}

// bucket is a token bucket.
type bucket struct {
	rate, burst, tokens float64
	last                time.Time
}

func newBucket(rate, burst float64, now time.Time) *bucket {
	return &bucket{rate: rate, burst: burst, tokens: burst, last: now}
}

func (b *bucket) refill(now time.Time) {
	if d := now.Sub(b.last).Seconds(); d > 0 {
		b.tokens = min(b.burst, b.tokens+d*b.rate)
		b.last = now
	}
}

func (b *bucket) take(now time.Time) bool {
	b.refill(now)
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (b *bucket) full(now time.Time) bool {
	b.refill(now)
	return b.tokens >= b.burst
}
