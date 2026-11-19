// SPDX-License-Identifier: GPL-2.0-or-later

package main

// LAN ports (platform jio-mtk, model UHDIW): the JCOW414's switch ports are
// reported as a UAP-IW-HD's (internal/jioports: front ports 1-3 = the
// unit's ports 1-3, UniFi port 4 absent, rear port 5 = the unit's port 4,
// the uplink), and in takeover mode the controller's port VLANs
// (system_cfg switch.*) are applied to the ports it may change: 2 and 3,
// and 1 only with ports_unlocked. The uplink never changes beyond the VLAN
// devices the VLAN SSIDs already put on it.
//
// The switch section arrives only once "Enable Port VLAN" is on in the
// device's settings, which the controller offers because the agent claims
// fw_caps QCA switch and OWRT switch (models.FWCapQCASwitch,
// FWCapOWRTSwitch) in takeover mode.

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// portState: ctr belongs to the loop goroutine; mgr and want to the
// worker goroutine.
type portState struct {
	ctr  *jioports.Counters
	mgr  *jioports.Manager // takeover only
	want *jioports.Want    // the last system_cfg's switch section
}

// portsOn reports whether the unit reports LAN ports (jio-mtk as UHDIW).
func (a *agent) portsOn() bool { return a.cfg.jio() && a.cfg.Model == "UHDIW" }

// portLocked: the uplink always, port 1 unless ports_unlocked lists it.
func (a *agent) portLocked(phys int) bool {
	if phys == jioports.UplinkPhys {
		return true
	}
	if phys != 1 {
		return false
	}
	for _, p := range a.cfg.PortsUnlocked {
		if p == phys {
			return false
		}
	}
	return true
}

// portsSetup builds the port manager (setup, takeover mode). It reports
// whether the agent applies port VLANs (the PortVLAN feature).
func (a *agent) portsSetup() bool {
	a.ports.ctr = jioports.NewCounters()
	if !a.portsOn() || !a.takeover.Load() || a.wifi == nil {
		return false
	}
	b, ok := a.wifi.(jioports.Bridger)
	if !ok {
		a.logf("ports: the Wi-Fi backend cannot bridge ports: port VLANs are not applied")
		return false
	}
	a.ports.mgr = jioports.New(jioports.Options{B: b, Unlocked: a.cfg.PortsUnlocked, DryRun: !a.cfg.Apply, Logf: a.logf,
		Uplink: func() string { u, _ := a.topo.uplinkName.Load().(string); return u }})
	var free []string
	for _, p := range jioports.LANPorts {
		if !a.portLocked(p) {
			free = append(free, fmt.Sprint(p))
		}
	}
	a.logf("ports: the controller's port VLANs apply to LAN port(s) %s (port 1 only with ports_unlocked; port 4 is the uplink)", strings.Join(free, ","))
	return true
}

// portFields gives the inform the UAP-IW-HD's five ports (loop goroutine).
func (a *agent) portFields(f map[string]any, s *apstate.Snapshot) {
	macs := map[int][]map[string]any{}
	for _, p := range s.Ports {
		for _, phys := range jioports.LANPorts {
			if p.Name == jioports.Untagged(phys) && p.BridgePort > 0 {
				macs[phys] = s.PortMACs(p.BridgePort)
			}
		}
	}
	if a.ports.ctr == nil {
		a.ports.ctr = jioports.NewCounters()
	}
	links := jioports.ReadLinks(a.o.root)
	f["port_table"] = jioports.Rows(jioports.RowsInput{Links: links, Stats: a.ports.ctr.Read(a.o.root),
		MACs: macs, Locked: a.portLocked})
	if it, ok := f["if_table"].([]map[string]any); ok && len(it) > 0 {
		it[0]["num_port"] = jioports.NumPorts
		// eth0.4.1's speed file says nothing (EINVAL): the switch's does
		if l := links[jioports.UplinkPhys]; l.Up {
			it[0]["speed"], it[0]["full_duplex"] = l.Speed, l.FullDuplex
		}
	}
	if rows, ok := f["lldp_table"].([]map[string]any); ok {
		for _, r := range rows {
			r["local_port_idx"] = jioports.UplinkIdx
		}
	}
}

// portsPrepare reads the switch section of pv and tells the Wi-Fi applier
// which VLAN bridges the ports keep, before the Wi-Fi apply (worker).
func (a *agent) portsPrepare(pv provision) {
	if a.ports.mgr == nil {
		return
	}
	w, notes := jioports.FromCfg(translate.ParseCfg(pv.systemCfg))
	a.ports.want = &w
	for _, n := range notes {
		a.ports.mgr.Note(n)
	}
	a.ports.mgr.Prepare(w)
}

// portsApply makes the last switch section live (worker: after a
// provision's Wi-Fi, and at every tick, where a port someone moved is put
// back). A port that fails is put back on the LAN; the configuration is
// acknowledged all the same (the Wi-Fi decides that).
func (a *agent) portsApply(ctx context.Context, why string) {
	if a.ports.mgr == nil || a.ports.want == nil {
		return
	}
	r := a.ports.mgr.Apply(ctx, *a.ports.want)
	a.portsReport(r, why)
}

func (a *agent) portsReport(r jioports.Report, why string) {
	for _, n := range r.Notes {
		a.ports.mgr.Note(n)
	}
	var ps []int
	for p := range r.Ports {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	for _, p := range ps {
		a.logf("ports: port %d (UniFi port %d) is %s (%s)", p, jioports.Idx(p), r.Ports[p], why)
	}
	ps = ps[:0]
	for p := range r.Failed {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	for _, p := range ps {
		a.event(fmt.Sprintf("ports: port %d: %v: put back on the untagged LAN", p, r.Failed[p]))
	}
	if r.Steps > 0 {
		a.count("port-change", r.Steps)
	}
}

// portsRestore puts the ports the controller may change back on the
// untagged LAN (the agent hands the unit back: dropToObserve).
func (a *agent) portsRestore(ctx context.Context) {
	if a.ports.mgr == nil {
		return
	}
	r := a.ports.mgr.Restore(ctx)
	a.portsReport(r, "handed back")
	a.ports.want = nil
}
