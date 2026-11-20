// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Native topology (docs/deco/topology-and-tplink-scrub.md): the unit shows
// up in UniFi like a U6-Lite with one Ethernet port.
//
//   - internal/lldp listens on both Ethernet ports and announces the AP on
//     the uplink every 30 s (chassis = AP MAC, port "eth0", TTL 120, system
//     name = hostname, Bridge + WLAN AP, the management IPv4);
//   - the inform carries the U6 Pro's shape: uplink "eth0", gateway_mac,
//     if_table with one row "eth0" holding the real uplink's counters and
//     speed, lldp_table rows for what is heard on the uplink, no
//     port_table;
//   - the uplink is tracked: the port with carrier the gateway's MAC was
//     learned on (br-lan FDB), else the one hearing the gateway's LLDP, else
//     the only port with carrier;
//   - loop guard (R9): when the gateway's LLDP or its MAC shows up on both
//     ports while both have carrier, the non-uplink port leaves br-lan
//     (takeover mode; observe mode only logs). It comes back when it loses
//     carrier, when the uplink loses carrier, or (LLDP evidence) when the
//     gateway is no longer heard on it; FDB-only evidence keeps it out until
//     its carrier drops (it can no longer learn the gateway's MAC once out).
//     A port re-added by someone else (netifd) is taken out again.
//     Observe mode changes nothing on the unit: a port an earlier takeover
//     run took out (record, loopFile) that the observe-mode start's
//     decosys.RestoreLoopGuard kept out stays tracked as out, and when it
//     could come back that is logged, not done; it is forgotten only once a
//     reading shows it in br-lan again.

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/lldp"
)

// loopWindow: the gateway's MAC learned on both ports within this long
// (both with carrier) counts as a loop.
const loopWindow = 60 * time.Second

type topology struct {
	uplink   string
	removed  map[string]string    // port -> why it is out of br-lan ("lldp", "fdb")
	fdbSeen  map[string]time.Time // port -> when the gateway's MAC was last learned there
	loopSeen bool                 // observe mode: the loop was logged
	held     map[string]string    // observe mode: port -> why it could come back (logged once per reason)
	// delifQueued: port -> a delif job is queued and has not finished yet
	// (loop goroutine stores, worker deletes)
	delifQueued sync.Map
	announce    atomic.Pointer[lldpAnnounce]
	gwIP        atomic.Value // string: the gateway's IP (guest policy)
	gwMAC       atomic.Value // string: the gateway's MAC (guest policy: the only L2 peer guests may reach)
	uplinkName  atomic.Value // string: uplink, for the worker (port VLANs never change it)
}

type lldpAnnounce struct {
	port string
	src  net.HardwareAddr
	info lldp.Info
}

func newTopology() *topology {
	return &topology{removed: map[string]string{}, fdbSeen: map[string]time.Time{}, held: map[string]string{}}
}

// ethPorts are the unit's Ethernet ports from a reading, by name.
func ethPorts(s *apstate.Snapshot) map[string]apstate.Port {
	out := map[string]apstate.Port{}
	for _, p := range s.Ports {
		if strings.HasPrefix(p.Name, "eth") {
			out[p.Name] = p
		}
	}
	return out
}

// startLLDP runs the LLDP agent on the unit's Ethernet ports.
func (a *agent) startLLDP(ctx context.Context, s *apstate.Snapshot) {
	if a.o.noLLDP {
		return
	}
	var ports []string
	for n := range ethPorts(s) {
		ports = append(ports, n)
	}
	sort.Strings(ports)
	a.lldp = lldp.New(lldp.Options{Ports: ports, Open: a.o.lldpOpen, Every: a.t.lldpEvery, Logf: a.logf,
		Self: func() (string, net.HardwareAddr, lldp.Info, bool) {
			an := a.topo.announce.Load()
			if an == nil || an.port == "" {
				return "", nil, lldp.Info{}, false
			}
			return an.port, an.src, an.info, true
		}})
	a.bg.Add(1)
	go func() { defer a.bg.Done(); a.lldp.Run(ctx) }()
}

// gatewayMAC is the gateway's MAC from the ARP table ("" = unknown).
func gatewayMAC(s *apstate.Snapshot) string {
	if s.Gateway == "" {
		return ""
	}
	var macs []string
	for mac, ip := range s.ARP {
		if ip == s.Gateway {
			macs = append(macs, strings.ToLower(mac))
		}
	}
	sort.Strings(macs)
	if len(macs) == 0 {
		return ""
	}
	return macs[0]
}

// fdbPortOf is the Ethernet port mac was learned on ("" = none).
func fdbPortOf(s *apstate.Snapshot, mac string) string {
	if mac == "" {
		return ""
	}
	for _, e := range s.FDB {
		if e.Local || !strings.EqualFold(e.MAC, mac) {
			continue
		}
		for _, p := range s.Ports {
			if p.BridgePort != 0 && p.BridgePort == e.Port && strings.HasPrefix(p.Name, "eth") {
				return p.Name
			}
		}
	}
	return ""
}

// observeReading tracks the uplink, runs the loop guard and steering, and
// rewrites the inform's port fields (loop goroutine).
func (a *agent) observeReading(s *apstate.Snapshot, f map[string]any) {
	now := a.o.now()
	t := a.topo
	ports := ethPorts(s)
	gw := gatewayMAC(s)
	fdbPort := fdbPortOf(s, gw)
	if fdbPort != "" {
		t.fdbSeen[fdbPort] = now
	}
	// A sighting from before a carrier loss is no loop evidence: when the
	// cable moves (the uplink moves with it), the old uplink's sighting of
	// the gateway's MAC must not take that port out should it regain
	// carrier within loopWindow. It is not cleared on every uplink move:
	// in a real loop the MAC flaps between ports with carrier, which moves
	// the uplink each reading, and those sightings are the evidence.
	for p := range t.fdbSeen {
		if pp, ok := ports[p]; !ok || !pp.Up {
			delete(t.fdbSeen, p)
		}
	}
	var lldpPorts []string
	if a.lldp != nil && (gw != "" || s.Gateway != "") {
		lldpPorts = a.lldp.PortsHearing(gw, s.Gateway)
	}
	t.gwIP.Store(s.Gateway)
	if gw != "" {
		t.gwMAC.Store(gw)
	}

	// uplink
	var carrier []string
	for n, p := range ports {
		if p.Up && t.removed[n] == "" {
			carrier = append(carrier, n)
		}
	}
	sort.Strings(carrier)
	up := t.uplink
	switch hearing := intersect(lldpPorts, carrier); {
	case a.cfg.jio():
		// the JCOW414's uplink is its WAN socket, by wiring: a gateway MAC
		// seen on a LAN port (a downstream router reflecting the LAN, seen
		// 2026-11-19 on port 1) must not move it, or SetUplink and the
		// port code would treat the tenant's port as the uplink
		up = jioports.Untagged(jioports.UplinkPhys)
	case contains(carrier, fdbPort):
		up = fdbPort
	case len(hearing) == 1:
		up = hearing[0]
	case len(carrier) == 1:
		up = carrier[0]
	}
	if up != t.uplink {
		if t.uplink != "" {
			a.event(fmt.Sprintf("uplink moved from %s to %s", t.uplink, up))
		} else {
			a.logf("uplink: %s", up)
		}
		t.uplink, a.uplink = up, up
		t.uplinkName.Store(up)
		if a.takeover.Load() && a.wifi != nil {
			// VLAN devices follow at the next plan or tick (bcmwifi)
			a.submit("uplink "+up, func(context.Context) { a.wifi.SetUplink(up) })
		}
	}

	if !a.cfg.jio() {
		// the JCOW414's bridge (bdg2) has a downstream router on another
		// port by design; the loop guard acts on the Deco's br-lan only
		a.loopGuard(ports, lldpPorts, now)
	}

	if mac, err := net.ParseMAC(s.MAC); err == nil && t.uplink != "" {
		info := lldp.Info{ChassisMAC: mac, PortID: "eth0", TTL: 120, SysName: s.Hostname,
			SysDescr: a.profile.Display + " " + a.x.S.Version, Caps: lldp.CapBridge | lldp.CapWLANAP,
			MgmtIPv4: net.ParseIP(s.IP), IfIndex: a.ifIndex(t.uplink)}
		t.announce.Store(&lldpAnnounce{port: t.uplink, src: mac, info: info})
	}

	a.uplinkFields(f, s, ports, gw)
	if a.portsOn() {
		a.portFields(f, s)
	}
	a.clientsReading(s, now)
}

// clientsReading is band steering and the Roaming Assistant for one reading
// (loop goroutine). The worker's Roaming Assistant outcomes are applied
// first, on a stale reading too: a request that succeeded keeps band
// steering off the client from this reading on, so a client that went to
// this unit's 2.4 GHz BSS instead of the other AP is not asked straight
// back to 5 GHz.
func (a *agent) clientsReading(s *apstate.Snapshot, now time.Time) {
	a.roamOutcomes()
	a.no2ghzReading(s, now) // before band steering, which then leaves its clients alone
	a.steerReading(s, now)
	if !a.stale {
		a.roamReading(s, now)
	}
	a.minRSSIReading(s, now) // minrssi.go
}

// loopGuard is R9 (loop goroutine; the changes run on the worker).
func (a *agent) loopGuard(ports map[string]apstate.Port, lldpPorts []string, now time.Time) {
	t := a.topo
	upPort, upOK := ports[t.uplink]
	// bring back what no longer needs to be out
	for p, why := range t.removed {
		pp, ok := ports[p]
		reason := ""
		switch {
		case !ok || !pp.Up:
			reason = p + " lost carrier"
		case !upOK || !upPort.Up:
			reason = "the uplink " + t.uplink + " lost carrier"
		case why == "lldp" && !contains(lldpPorts, p):
			reason = "the gateway's LLDP is no longer heard on " + p
		}
		if !a.takeover.Load() {
			a.observeRemoved(p, pp, ok, reason)
			continue
		}
		if reason == "" {
			if pp.BridgePort != 0 {
				if _, queued := t.delifQueued.Load(p); !queued {
					a.event("LOOP GUARD: " + p + " was put back into br-lan by someone else: taking it out again")
					a.queueDelif(p, why)
				}
			}
			continue
		}
		delete(t.removed, p)
		a.event("loop guard: " + reason + ": " + p + " back into br-lan")
		a.submit("loop guard "+p, func(ctx context.Context) { a.bridgePort(ctx, p, "", true) })
	}
	if t.uplink == "" || !upOK || !upPort.Up {
		return
	}
	for p, pp := range ports {
		if p == t.uplink || !pp.Up || t.removed[p] != "" {
			continue
		}
		why := ""
		if contains(lldpPorts, p) && contains(lldpPorts, t.uplink) {
			why = "lldp"
		} else if s1, s2 := t.fdbSeen[p], t.fdbSeen[t.uplink]; !s1.IsZero() && !s2.IsZero() && now.Sub(s1) < loopWindow && now.Sub(s2) < loopWindow {
			why = "fdb"
		}
		if why == "" {
			continue
		}
		evidence := map[string]string{"lldp": "the gateway's LLDP is heard", "fdb": "the gateway's MAC was learned"}[why]
		if !a.takeover.Load() {
			if !t.loopSeen {
				t.loopSeen = true
				a.event(fmt.Sprintf("LOOP: %s on both %s and %s (observe mode: nothing is changed)", evidence, t.uplink, p))
			}
			continue
		}
		t.removed[p] = why
		a.event(fmt.Sprintf("!!!!! LOOP GUARD: %s on both %s (uplink) and %s: taking %s out of br-lan !!!!!", evidence, t.uplink, p, p))
		a.queueDelif(p, why)
	}
}

// queueDelif queues taking port out of br-lan (loop goroutine). Until the
// job has run, readings still show the port in br-lan: delifQueued keeps the
// "put back by someone else" path from queueing it again on every reading.
func (a *agent) queueDelif(port, why string) {
	t := a.topo
	t.delifQueued.Store(port, true)
	select {
	case a.jobs <- job{"loop guard " + port, func(ctx context.Context) {
		defer t.delifQueued.Delete(port)
		a.bridgePort(ctx, port, why, false)
	}}:
	default:
		t.delifQueued.Delete(port)
		a.logf("wifi worker: queue full, dropped loop guard %s", port)
	}
}

// observeRemoved is the loop guard in observe mode for a port recorded as
// out of br-lan (loop goroutine). Observe mode changes nothing on the unit
// (docs/deco/agent-design.md): the only bring-back is the observe-mode
// start's decosys.RestoreLoopGuard, and the worker that runs brctl jobs
// runs only in takeover. So the port stays tracked as out, which it is, and
// a reason to bring it back is logged instead of acted on; it is forgotten
// only when a reading shows it in br-lan again.
func (a *agent) observeRemoved(p string, pp apstate.Port, ok bool, reason string) {
	t := a.topo
	if ok && pp.BridgePort != 0 {
		delete(t.removed, p)
		delete(t.held, p)
		a.event("loop guard: " + p + " is in br-lan again: no longer tracked as out (observe mode)")
		return
	}
	if reason == "" {
		delete(t.held, p)
		return
	}
	if t.held[p] == reason {
		return
	}
	t.held[p] = reason
	a.event("loop guard: " + reason + ": " + p + " could go back into br-lan, but observe mode changes nothing: it stays out " +
		"(restarting the agent puts it back when safe, decosys.RestoreLoopGuard; a reboot rebuilds br-lan)")
}

// bridgePort adds port to br-lan or takes it out (worker). Either way the
// flow cache then forgets the port's flows (R21: brctl addif/delif evicts
// nothing, so flows learned before keep their old path), and the run-dir
// record of the ports taken out follows (loopFile).
func (a *agent) bridgePort(ctx context.Context, port, why string, in bool) {
	op := map[bool]string{true: "addif", false: "delif"}[in]
	if _, err := a.o.run.Run(ctx, "brctl", op, "br-lan", port); err != nil {
		a.logf("loop guard: brctl %s br-lan %s: %v", op, port, err)
		return
	}
	a.recordLoopGuard(port, why, in)
	if err := a.sys.FlushFlows(ctx, decosys.FlowScope{Dev: port}); err != nil {
		a.logf("loop guard: flow cache: %v", err)
	}
	a.o.col.Invalidate()
}

// loopFile records, in the run directory, the ports the loop guard took out
// of br-lan ("<port> <why>" per line). It is on ramfs on purpose: a reboot
// rebuilds br-lan with both ports and the record goes with it. A restarted
// agent (crash, deploy, R4 exit) reloads it, so a port an earlier run took
// out still comes back when it loses carrier or the uplink does. Without it
// the port stays out for good: FDB evidence cannot be seen on a port outside
// br-lan, and should that port later carry the only cable, the unit would
// have no bridged uplink and be cut off until a reboot.
const loopFile = "loopguard"

func (a *agent) loopFilePath() string { return a.dev(filepath.Join(a.o.runDir, loopFile)) }

// loadLoopGuard returns the ports an earlier run took out of br-lan.
func loadLoopGuard(path string) map[string]string {
	out := map[string]string{}
	b, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) == 2 && strings.HasPrefix(f[0], "eth") {
			out[f[0]] = f[1]
		}
	}
	return out
}

// recordLoopGuard updates loopFile after a successful brctl (worker only).
func (a *agent) recordLoopGuard(port, why string, in bool) {
	path := a.loopFilePath()
	m := loadLoopGuard(path)
	if in {
		delete(m, port)
	} else {
		if why == "" {
			why = "fdb"
		}
		m[port] = why
	}
	var lines []string
	for _, p := range sortedKeys(m) {
		lines = append(lines, p+" "+m[p])
	}
	tmp := path + ".tmp"
	err := os.MkdirAll(filepath.Dir(path), 0o700)
	if err == nil {
		err = os.WriteFile(tmp, []byte(strings.Join(lines, "\n")+"\n"), 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		a.logf("loop guard: recording %s: %v (a restarted agent would not know %s is out of br-lan)", path, err, port)
	}
}

// ifIndex reads a port's interface index (0 = unknown).
func (a *agent) ifIndex(port string) uint32 {
	b, err := os.ReadFile(a.dev(filepath.Join("/sys/class/net", port, "ifindex")))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	return uint32(n)
}

// uplinkFields gives the inform the U6 Pro's port shape
// (docs/reference/u6pro/mca-dump.json): one wired port, eth0.
func (a *agent) uplinkFields(f map[string]any, s *apstate.Snapshot, ports map[string]apstate.Port, gw string) {
	t := a.topo
	f["uplink"] = "eth0"
	f["has_eth1"] = false
	delete(f, "port_table")
	if gw != "" {
		f["gateway_mac"] = gw
	}
	if p, ok := ports[t.uplink]; ok {
		speed := p.Speed
		if !p.Up || speed < 0 {
			speed = 0
		}
		// The row a wired U6 Pro sends (docs/reference/u6pro/mca-dump*.json,
		// inform-field-inventory.tsv): counters as integers, errors, drops
		// and rx_multicast included, and no wireless keys (signal, rssi,
		// is_mesh_v3): this unit never meshes, and a wired U6 Pro's row
		// has none. ip/netmask are extra to the real row but kept.
		f["if_table"] = []map[string]any{{
			"name": "eth0", "mac": s.MAC, "ip": s.IP, "netmask": s.Netmask, "up": p.Up,
			"speed": speed, "full_duplex": p.Up && p.FullDuplex, "num_port": 1,
			"rx_bytes": p.RxBytes, "tx_bytes": p.TxBytes, "rx_packets": p.RxPkts, "tx_packets": p.TxPkts,
			"rx_errors": p.RxErrors, "tx_errors": p.TxErrors, "rx_dropped": p.RxDropped, "tx_dropped": p.TxDropped,
			"rx_multicast": p.RxMulticast,
		}}
	} else if it, ok := f["if_table"].([]map[string]any); ok && len(it) > 0 {
		it[0]["num_port"] = 1
		for _, k := range []string{"signal", "rssi", "is_mesh_v3"} {
			delete(it[0], k)
		}
	}
	// A real U6 Pro sends no top-level "stat" (study-inform-payload.md);
	// the client counts stay in num_sta / user-num_sta and vap_table.
	delete(f, "stat")
	rows := []map[string]any{}
	if a.lldp != nil && t.uplink != "" {
		for _, n := range a.lldp.Neighbors(t.uplink) {
			ips := n.MgmtIPs
			if ips == nil {
				ips = []string{}
			}
			rows = append(rows, map[string]any{
				"chassis_id": n.ChassisID, "chassis_id_subtype": lldp.ChassisSubtypeName(n.ChassisIDSubtype),
				"is_wired": true, "local_port_idx": 1, "local_port_name": "eth0", "mgmt_ips": ips, "port_id": n.PortID,
			})
		}
	}
	f["lldp_table"] = rows
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s && s != "" {
			return true
		}
	}
	return false
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		if contains(b, x) {
			out = append(out, x)
		}
	}
	return out
}
