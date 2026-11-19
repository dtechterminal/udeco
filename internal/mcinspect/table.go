// SPDX-License-Identifier: GPL-2.0-or-later

package mcinspect

import (
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
)

// Limits on what one VAP and one client keep (a client sending to
// thousands of groups or service names must not grow the agent).
const (
	maxClients     = 256 // per VAP
	maxGroups      = 64  // per client (rx) and per VAP (tx)
	maxServices    = 64  // per client
	maxMembers     = 64  // per client
	reportGroups   = 32  // groups rows per client in one inform
	reportServices = 32  // services rows per client in one inform
	// MembershipAge is how long a membership lives without a new report:
	// the U6 Pro's IGMP snooping ageing (sysinit/mcsd.conf "aging 260").
	MembershipAge = 260 * time.Second
)

type counters struct{ rxBytes, rxPkts, txBytes, txPkts int64 }

type groupKey struct {
	typ   string
	group netip.Addr
	port  int
}

type service struct{ bytes, pkts int64 }

type member struct{ first, last time.Time }

type client struct {
	types    map[string]*counters // rx only
	groups   map[groupKey]*counters
	services map[string]*service
	rr       map[string]int64
	members  map[netip.Addr]*member
}

// vap holds what the VAP sent (tx: the same for every client on it, as a
// real AP reports it) and its clients' rx accounting.
type vap struct {
	types   map[string]*counters // tx only
	groups  map[groupKey]*counters
	clients map[string]*client
}

// Table is the multicast accounting of every inspected VAP. It is safe for
// concurrent use: the per-VAP readers write, the inform loop reads.
type Table struct {
	mu   sync.Mutex
	vaps map[string]*vap
}

func NewTable() *Table { return &Table{vaps: map[string]*vap{}} }

// Observe accounts one frame seen on the VAP vif: outgoing frames are what
// the VAP sent to its clients, the others what a client sent. Frames that
// are not group-addressed are ignored.
func (t *Table) Observe(vif string, b []byte, length int, outgoing bool, now time.Time) {
	f, ok := Classify(b, length)
	if !ok || !f.IsGroup {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaps[vif]
	if v == nil {
		v = &vap{types: map[string]*counters{}, groups: map[groupKey]*counters{}, clients: map[string]*client{}}
		t.vaps[vif] = v
	}
	k := groupKey{f.Type, f.Group, f.Port}
	n := int64(f.Len)
	if outgoing {
		c := get(v.types, f.Type, maxInt)
		c.txBytes, c.txPkts = c.txBytes+n, c.txPkts+1
		if g := get(v.groups, k, maxGroups); g != nil {
			g.txBytes, g.txPkts = g.txBytes+n, g.txPkts+1
		}
		return
	}
	if f.SrcGroup {
		return // a group address as source is not a client
	}
	cl := v.clients[f.Src]
	if cl == nil {
		if len(v.clients) >= maxClients {
			return
		}
		cl = &client{types: map[string]*counters{}, groups: map[groupKey]*counters{},
			services: map[string]*service{}, rr: map[string]int64{}, members: map[netip.Addr]*member{}}
		v.clients[f.Src] = cl
	}
	c := get(cl.types, f.Type, maxInt)
	c.rxBytes, c.rxPkts = c.rxBytes+n, c.rxPkts+1
	if g := get(cl.groups, k, maxGroups); g != nil {
		g.rxBytes, g.rxPkts = g.rxBytes+n, g.rxPkts+1
	}
	for _, a := range f.Join {
		if m := cl.members[a]; m != nil {
			m.last = now
		} else if len(cl.members) < maxMembers {
			cl.members[a] = &member{first: now, last: now}
		}
	}
	for _, a := range f.Leave {
		delete(cl.members, a)
	}
	if f.MDNS != nil {
		for _, r := range f.MDNS.RR {
			cl.rr[r]++
		}
		for _, s := range f.MDNS.Services {
			if sv := get(cl.services, s, maxServices); sv != nil {
				sv.bytes, sv.pkts = sv.bytes+n, sv.pkts+1
			}
		}
	}
}

const maxInt = int(^uint(0) >> 1)

// get returns m[k], creating it while m has fewer than limit entries (nil
// when it is full).
func get[K comparable, V any](m map[K]*V, k K, limit int) *V {
	if p := m[k]; p != nil {
		return p
	}
	if len(m) >= limit {
		return nil
	}
	p := new(V)
	m[k] = p
	return p
}

// Retain forgets the clients of vif that are not in stations (they left);
// their counters start from zero when they come back, as on a real AP.
func (t *Table) Retain(vif string, stations []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaps[vif]
	if v == nil {
		return
	}
	keep := map[string]bool{}
	for _, s := range stations {
		keep[strings.ToLower(s)] = true
	}
	for m := range v.clients {
		if !keep[m] {
			delete(v.clients, m)
		}
	}
}

// Drop forgets a VAP that is no longer inspected.
func (t *Table) Drop(vif string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.vaps, vif)
}

// Block is the sta_table[].multicast block for client mac on vif, in the
// U6 Pro's shape: types (all of Types: rx from the client, tx the VAP's),
// groups, memberships, services and mdns_rr (only when the client sent
// mDNS records). ok is false when vif is not inspected.
func (t *Table) Block(vif, mac string, now time.Time) (map[string]any, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	v := t.vaps[vif]
	if v == nil {
		return nil, false
	}
	cl := v.clients[strings.ToLower(mac)]
	if cl == nil {
		cl = &client{}
	}
	types := map[string]any{}
	for _, ty := range Types {
		var c counters
		if r := cl.types[ty]; r != nil {
			c.rxBytes, c.rxPkts = r.rxBytes, r.rxPkts
		}
		if x := v.types[ty]; x != nil {
			c.txBytes, c.txPkts = x.txBytes, x.txPkts
		}
		types[ty] = map[string]any{"rx_bytes": c.rxBytes, "rx_pkts": c.rxPkts, "tx_bytes": c.txBytes, "tx_pkts": c.txPkts}
	}
	merged := map[groupKey]counters{}
	for k, c := range cl.groups {
		m := merged[k]
		m.rxBytes, m.rxPkts = c.rxBytes, c.rxPkts
		merged[k] = m
	}
	for k, c := range v.groups {
		m := merged[k]
		m.txBytes, m.txPkts = c.txBytes, c.txPkts
		merged[k] = m
	}
	keys := make([]groupKey, 0, len(merged))
	for k := range merged {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := merged[keys[i]], merged[keys[j]]
		if x, y := a.rxPkts+a.txPkts, b.rxPkts+b.txPkts; x != y {
			return x > y
		}
		if keys[i].typ != keys[j].typ {
			return keys[i].typ < keys[j].typ
		}
		if c := keys[i].group.Compare(keys[j].group); c != 0 {
			return c < 0
		}
		return keys[i].port < keys[j].port
	})
	groups := []map[string]any{}
	for _, k := range keys[:min(len(keys), reportGroups)] {
		c := merged[k]
		row := map[string]any{"type": k.typ, "group_ip": k.group.String(), "dst_port": k.port}
		// the real AP leaves a direction's keys out when it saw nothing
		if c.rxPkts > 0 {
			row["rx_bytes"], row["rx_pkts"] = c.rxBytes, c.rxPkts
		}
		if c.txPkts > 0 {
			row["tx_bytes"], row["tx_pkts"] = c.txBytes, c.txPkts
		}
		groups = append(groups, row)
	}
	mems := []map[string]any{}
	addrs := make([]netip.Addr, 0, len(cl.members))
	for a, m := range cl.members {
		if now.Sub(m.last) > MembershipAge {
			delete(cl.members, a)
			continue
		}
		addrs = append(addrs, a)
	}
	sort.Slice(addrs, func(i, j int) bool { return addrs[i].Compare(addrs[j]) < 0 })
	for _, a := range addrs {
		mems = append(mems, map[string]any{"group_ip": a.String(), "age_ms": max(int64(0), now.Sub(cl.members[a].first).Milliseconds())})
	}
	names := make([]string, 0, len(cl.services))
	for n := range cl.services {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool {
		if a, b := cl.services[names[i]].pkts, cl.services[names[j]].pkts; a != b {
			return a > b
		}
		return names[i] < names[j]
	})
	svcs := []map[string]any{}
	for _, n := range names[:min(len(names), reportServices)] {
		s := cl.services[n]
		svcs = append(svcs, map[string]any{"name": n, "bytes": s.bytes, "pkts": s.pkts})
	}
	out := map[string]any{"types": types, "groups": groups, "memberships": mems, "services": svcs}
	if len(cl.rr) > 0 {
		rr := map[string]any{}
		for k, n := range cl.rr {
			rr[k] = n
		}
		out["mdns_rr"] = rr
	}
	return out, true
}
