// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Gratuitous ARP on association (docs/deco/features/assoc-garp.md). When
// a station is authorized on one of the agent's BSSes (AP-STA-CONNECTED,
// handled as the control socket delivers it: hapdmon's OnEvent hook, not
// the next reading) and its IPv4 address is known on that BSS's bridge
// (its DHCP ACK or its own frames seen by the connection-event taps within
// staIPKeep on a BSS of the same bridge; else, on br-lan only, the last
// reading's ARP table, which is the AP's own and so br-lan's), the agent
// sends one gratuitous ARP on its behalf (from its MAC, its address as
// sender and target) on each wired port of that bridge: the switches move
// the station's MAC to this AP at once instead of when it next sends,
// which shortens the gap after a roam. An address seen on another bridge
// (another network) is never announced. Never before authorization, at
// most once per garpEvery per station, never on a Wi-Fi port. assoc_garp
// false turns it off.

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/stasnoop"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

const garpEvery = 10 * time.Second

type garpState struct {
	last   map[string]time.Time // station -> the last GARP sent
	failed bool                 // a send failure was logged
	q      chan hapdmon.Event   // authorizations from the socket monitor (onHapdEvent)
}

// mgmtBridge is the bridge the AP's own address (and so its ARP table) is
// on.
const mgmtBridge = unit.LANBridge

// onHapdEvent is hapdmon's OnEvent hook (its goroutine): an authorization
// is queued for the GARP goroutine; a full queue drops it.
func (a *agent) onHapdEvent(ev hapdmon.Event) {
	if ev.Kind != hapdmon.Connected {
		return
	}
	q := a.garpQueue()
	select {
	case q <- ev:
	default:
	}
}

func (a *agent) garpQueue() chan hapdmon.Event {
	a.garpOnce.Do(func() { a.garp.q = make(chan hapdmon.Event, 32) })
	return a.garp.q
}

// startGARP runs the GARP goroutine: it owns a.garp's other fields.
func (a *agent) startGARP(ctx context.Context) {
	q := a.garpQueue()
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		for {
			select {
			case <-ctx.Done():
				return
			case ev := <-q:
				var arp map[string]string
				if p := a.garpARP.Load(); p != nil {
					arp = *p
				}
				a.assocGARP(ev, time.Now(), arp)
			}
		}
	}()
}

// assocGARPOn: on unless assoc_garp is false.
func (c *Config) assocGARPOn() bool { return c.AssocGARP == nil || *c.AssocGARP }

// assocGARP handles one authorization (the GARP goroutine); arp is the
// last reading's ARP table (station -> address), a fallback on br-lan.
func (a *agent) assocGARP(ev hapdmon.Event, now time.Time, arp map[string]string) {
	if ev.Kind != hapdmon.Connected || a.conn == nil || !a.cfg.assocGARPOn() || !a.takeover.Load() {
		return
	}
	br := a.bridgeName(ev.Vif)
	if br == "" {
		return
	}
	ip, ok := a.conn.t.ipOf(ev.MAC, br, now)
	if !ok && br == mgmtBridge {
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

// bridgeName is vif's bridge (sysfs; "" when it is in none).
func (a *agent) bridgeName(vif string) string {
	link, err := os.Readlink(filepath.Join(a.o.root, "sys/class/net", vif, "brport", "bridge"))
	if err != nil {
		return ""
	}
	return filepath.Base(link)
}

// wiredPorts are the non-Wi-Fi members of vif's bridge (sysfs).
func (a *agent) wiredPorts(vif string) []string {
	br := a.bridgeName(vif)
	if br == "" {
		return nil
	}
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
