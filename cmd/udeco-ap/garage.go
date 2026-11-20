// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
)

// The Garage's (platform jio-mtk) per-reading Wi-Fi jobs: what a U6's
// stamgr and wevent do with each look at the clients
// (docs/deco/features/garage-parity.md).

// weakKicker is the applier's minimum RSSI kick (mtkwifi minrssi.go).
type weakKicker interface {
	KickWeak(context.Context, *apstate.Snapshot) []string
}

// garageReading runs after a fresh reading's station events were taken
// (loop goroutine). The kicked stations' leaves carry assoc_status 16.
func (a *agent) garageReading(ctx context.Context, s *apstate.Snapshot) {
	if !a.cfg.jio() || !a.takeover.Load() {
		return
	}
	if k, ok := a.wifi.(weakKicker); ok {
		a.sta.kicked(k.KickWeak(ctx, s))
	}
	if g, ok := a.wifi.(garageNet); ok {
		a.garageStations(ctx, g, s)
	}
	if r, ok := a.wifi.(radarSource); ok {
		for _, e := range r.TakeRadar() {
			a.event(fmt.Sprintf("RADAR on 5 GHz channel %d: the radio moved to %d; back after the 30 min non-occupancy period", e.Channel, e.MovedTo))
			a.sta.push(map[string]any{"event_string": "EVT_AP_RadarDetected", "radio": "na", "radio_name": "wifi1",
				"channel": e.Channel, "freq": e.Freq})
		}
	}
}

// radarSource is the applier's DFS radar detections (mtkwifi dfs.go).
type radarSource interface {
	TakeRadar() []mtkwifi.RadarEvent
}

// garageNet is the applier's proxy ARP responder and station
// announcement (mtkwifi proxyarp.go, garp.go).
type garageNet interface {
	ProxyARPStations(map[string][]string)
	Neighbor(mac string) (net.IP, bool)
	AnnounceStation(ctx context.Context, vif, mac string, ip net.IP) error
}

// garageNetState: the stations of the last reading (MAC -> BSS netdev),
// the addresses seen (MAC -> IPv4), when each station was last announced.
type garageNetState struct {
	seeded bool
	seen   map[string]string
	ips    map[string]string
	garp   map[string]time.Time
}

const (
	garpGap   = 30 * time.Second // a station is announced at most this often
	garageIPs = 1024             // addresses kept for stations that come back
)

// garageStations gives the responder this reading's stations and
// announces each station new on a BSS whose address is known (U6: a GARP
// for a client that roamed in), not for the first reading's nor while
// the radios restart (its stations come back to the same unit).
func (a *agent) garageStations(ctx context.Context, g garageNet, s *apstate.Snapshot) {
	st := &a.gnet
	if st.ips == nil {
		st.ips, st.garp = map[string]string{}, map[string]time.Time{}
	}
	byVif, cur := map[string][]string{}, map[string]string{}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			for _, sta := range v.Stations {
				m := strings.ToLower(sta.MAC)
				byVif[v.Iface] = append(byVif[v.Iface], m)
				cur[m] = v.Iface
			}
		}
	}
	g.ProxyARPStations(byVif)
	for m, ip := range s.ARP {
		if p := net.ParseIP(ip).To4(); p != nil {
			if _, ok := st.ips[strings.ToLower(m)]; !ok && len(st.ips) >= garageIPs {
				clear(st.ips)
			}
			st.ips[strings.ToLower(m)] = p.String()
		}
	}
	now := time.Now()
	if st.seeded && !a.radiosBusy() {
		macs := make([]string, 0, len(cur))
		for m := range cur {
			macs = append(macs, m)
		}
		sort.Strings(macs)
		for _, m := range macs {
			vif := cur[m]
			if st.seen[m] == vif || now.Sub(st.garp[m]) < garpGap {
				continue
			}
			ip := net.ParseIP(st.ips[m]).To4()
			if ip == nil {
				if n, ok := g.Neighbor(m); ok {
					ip = n.To4()
				}
			}
			if ip == nil {
				continue
			}
			if err := g.AnnounceStation(ctx, vif, m, ip); err != nil {
				a.logf("GARP for %s on %s: %v", m, vif, err)
				continue
			}
			st.garp[m] = now
		}
	}
	for m, t := range st.garp {
		if now.Sub(t) >= garpGap {
			delete(st.garp, m)
		}
	}
	st.seen, st.seeded = cur, true
}

// leaveSource is the Garage's driver leave monitor (mtkwifi.Events).
type leaveSource interface {
	Take() ([]hapdmon.Event, int)
}

// leaveWakeGap: a released leave wakes the loop at most this often.
const leaveWakeGap = 2 * time.Second

var lastLeaveWake atomic.Int64

// startDriverEvents follows the MediaTek drivers' station events
// (rtnetlink, ECNT, the MT7603's Del Sta lines): a leave reaches the
// controller with the next inform, which it brings forward
// (mtkwifi/drvevents.go). Takeover only; passive listeners.
func (a *agent) startDriverEvents(ctx context.Context) {
	if a.o.drvEv != nil {
		a.drv = a.o.drvEv
		return
	}
	type parpHooks interface {
		ProxyARPRequest(*mtkwifi.ProxyARPRequest)
		ProxyARPDown(context.Context)
		SetEventsHealthy(func() bool)
	}
	m := mtkwifi.NewEvents(mtkwifi.EventsOptions{Logf: a.logf, Busy: a.radiosBusy, NG2: true,
		ProxyARP: func(r *mtkwifi.ProxyARPRequest) {
			if p, ok := a.wifi.(parpHooks); ok {
				p.ProxyARPRequest(r)
			}
		},
		Down: func() {
			if p, ok := a.wifi.(parpHooks); ok {
				p.ProxyARPDown(ctx)
			}
		},
		Notify: func() {
			now := time.Now().UnixNano()
			if last := lastLeaveWake.Load(); now-last >= int64(leaveWakeGap) && lastLeaveWake.CompareAndSwap(last, now) {
				a.wakeLoop()
			}
		}})
	a.drv = m
	if p, ok := a.wifi.(parpHooks); ok {
		p.SetEventsHealthy(m.Healthy)
	}
	a.bg.Add(1)
	go func() { defer a.bg.Done(); m.Run(ctx) }()
}

// radiosBusy: the Wi-Fi applier is changing the radios or a restart
// settles (its RestartGate refuses a driver read): driver events of that
// time are the restart's own.
func (a *agent) radiosBusy() bool {
	if a.wifiBusy.Load() {
		return true
	}
	g, ok := a.wifi.(mtkwifi.RestartGate)
	if !ok {
		return false
	}
	done, ok := g.DriverRead()
	if ok {
		done()
	}
	return !ok
}

// uplinkIsolator is the applier's uplink-loss isolation (mtkwifi
// uplinkloss.go).
type uplinkIsolator interface {
	SetUplinkDown(context.Context, bool) error
}

// uplinkState is the uplink-loss loop's state.
type uplinkState struct {
	w        mtkwifi.UplinkWatch
	isolated bool
}

// uplinkPoll: how often the uplink port's carrier is read.
const uplinkPoll = time.Second

// startUplinkLoss follows the uplink port's carrier (uplink_loss, on by
// default on the Garage; takeover with apply).
func (a *agent) startUplinkLoss(ctx context.Context) {
	if !a.cfg.uplinkLoss() || !a.cfg.Apply {
		return
	}
	if _, ok := a.wifi.(uplinkIsolator); !ok {
		return
	}
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		var st uplinkState
		t := time.NewTicker(uplinkPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				a.uplinkStep(ctx, &st, now)
			}
		}
	}()
}

// uplinkStep reads the uplink port's carrier once and isolates or
// restores the SSIDs when UplinkWatch says so. No switch reading (the
// port missing) is no decision.
func (a *agent) uplinkStep(ctx context.Context, st *uplinkState, now time.Time) {
	l, ok := jioports.ReadLinks(a.o.root)[jioports.UplinkPhys]
	if !ok {
		return
	}
	iso := st.w.Observe(l.Up, now)
	if iso == st.isolated {
		return
	}
	st.isolated = iso
	u, ok := a.wifi.(uplinkIsolator)
	if !ok {
		return
	}
	if iso {
		a.event("UPLINK LOST: no carrier on the uplink port for 15 s: user and guest SSIDs go down, the management SSID stays up")
	} else {
		a.event("UPLINK BACK: carrier on the uplink port for 30 s: every SSID comes back")
	}
	if err := u.SetUplinkDown(ctx, iso); err != nil {
		a.logf("wifi: %v", err)
	}
}
