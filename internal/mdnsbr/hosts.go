// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import "time"

// The host cache: which services each host name offers, per VLAN, learnt
// from SRV records ("TV._airplay._tcp.local SRV ... tv.local"). A filter
// that only lets some services through still lets the address records and
// address questions of the hosts that offer them through: a client that
// found a printer must be able to resolve printer.local later.

const (
	maxHosts       = 1024 // per VLAN
	maxHostSvcs    = 16   // per host
	maxHostTTL     = time.Hour
	maxCacheVLANs  = 64
	minHostTTLSecs = 1
)

type hostSvc struct {
	n   name // the service-scoped name (instance), for Policy.service
	exp time.Time
}

type hostEntry map[string]hostSvc // service-scoped name key -> it

type hostCache struct {
	vlans map[int]map[string]hostEntry // vlan -> host key -> services
}

func newHostCache() *hostCache {
	return &hostCache{vlans: map[int]map[string]hostEntry{}}
}

// learn records the SRV records of a response from vlan; a record with TTL
// 0 (a goodbye) forgets the pairing.
func (c *hostCache) learn(vlan int, m *message, now time.Time) {
	for _, sec := range [][]record{m.an, m.ar} {
		for _, r := range sec {
			if r.typ != typeSRV || !r.n.scoped() || r.target.scoped() || len(r.target) == 0 {
				continue
			}
			hosts := c.vlans[vlan]
			if hosts == nil {
				if len(c.vlans) >= maxCacheVLANs {
					continue
				}
				hosts = map[string]hostEntry{}
				c.vlans[vlan] = hosts
			}
			hk, sk := r.target.key(), r.n.key()
			if r.ttl == 0 {
				delete(hosts[hk], sk)
				if len(hosts[hk]) == 0 {
					delete(hosts, hk)
				}
				continue
			}
			ttl := time.Duration(max(r.ttl, minHostTTLSecs)) * time.Second
			ttl = min(ttl, maxHostTTL)
			e := hosts[hk]
			if e == nil {
				if len(hosts) >= maxHosts {
					c.expire(hosts, now)
					if len(hosts) >= maxHosts {
						continue
					}
				}
				e = hostEntry{}
				hosts[hk] = e
			}
			if _, ok := e[sk]; !ok && len(e) >= maxHostSvcs {
				continue
			}
			e[sk] = hostSvc{n: r.n, exp: now.Add(ttl)}
		}
	}
}

func (c *hostCache) expire(hosts map[string]hostEntry, now time.Time) {
	for h, e := range hosts {
		for s, x := range e {
			if !now.Before(x.exp) {
				delete(e, s)
			}
		}
		if len(e) == 0 {
			delete(hosts, h)
		}
	}
}

// view is the cache of one VLAN at a moment, as a hostSet.
func (c *hostCache) view(vlan int, now time.Time) hostSet {
	return hostView{c: c, vlan: vlan, now: now}
}

type hostView struct {
	c    *hostCache
	vlan int
	now  time.Time
}

func (v hostView) allowedHost(n name, p *Policy) bool {
	e := v.c.vlans[v.vlan][n.key()]
	for _, x := range e {
		if v.now.Before(x.exp) && p.service(x.n) {
			return true
		}
	}
	return false
}
