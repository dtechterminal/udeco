// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Gratuitous ARP on association (docs/deco/features/assoc-garp.md). When
// a station is authorized on one of the agent's BSSes (AP-STA-CONNECTED)
// and its IPv4 address is known (its DHCP ACK or its own frames seen by
// the connection-event taps within staIPKeep, else the reading's ARP
// table), the agent sends one gratuitous ARP on its behalf (from its MAC,
// its address as sender and target) on each wired port of its BSS's
// bridge: the switches move the station's MAC to this AP at once instead
// of when it next sends, which shortens the gap after a roam. Never before
// authorization, at most once per garpEvery per station, never on a Wi-Fi
// port. assoc_garp false turns it off.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/stasnoop"
)

const garpEvery = 10 * time.Second

type garpState struct {
	last   map[string]time.Time // station -> the last GARP sent
	failed bool                 // a send failure was logged
}

// assocGARPOn: on unless assoc_garp is false.
func (c *Config) assocGARPOn() bool { return c.AssocGARP == nil || *c.AssocGARP }

// assocGARP handles one socket event (loop goroutine); arp is the
// reading's ARP table (station -> address), a fallback.
func (a *agent) assocGARP(ev hapdmon.Event, now time.Time, arp map[string]string) {
	if ev.Kind != hapdmon.Connected || a.conn == nil || !a.cfg.assocGARPOn() || !a.takeover.Load() {
		return
	}
	ip, ok := a.conn.t.ipOf(ev.MAC, now)
	if !ok {
		ip = arp[ev.MAC]
		if ip == "" {
			ip = arp[strings.ToUpper(ev.MAC)]
		}
	}
	if ip == "" {
		return
	}
	g := &a.garp
	if g.last == nil {
		g.last = map[string]time.Time{}
	}
	if t, ok := g.last[ev.MAC]; ok && now.Sub(t) < garpEvery {
		return
	}
	for m, t := range g.last {
		if now.Sub(t) >= garpEvery {
			delete(g.last, m)
		}
	}
	frame, err := stasnoop.GARP(ev.MAC, ip)
	if err != nil {
		return
	}
	ports := a.wiredPorts(ev.Vif)
	if len(ports) == 0 {
		return
	}
	g.last[ev.MAC] = now
	send := a.o.garpSend
	if send == nil {
		send = stasnoop.SendFrame
	}
	for _, p := range ports {
		if err := send(p, frame); err != nil && !g.failed {
			g.failed = true
			a.logf("gratuitous ARP for %s on %s: %v (further failures not logged)", ev.MAC, p, err)
		}
	}
}

// wiredPorts are the non-Wi-Fi members of vif's bridge (sysfs).
func (a *agent) wiredPorts(vif string) []string {
	link, err := os.Readlink(filepath.Join(a.o.root, "sys/class/net", vif, "brport", "bridge"))
	if err != nil {
		return nil
	}
	br := filepath.Base(link)
	ents, err := os.ReadDir(filepath.Join(a.o.root, "sys/class/net", br, "brif"))
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); !strings.HasPrefix(n, "wl") {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
