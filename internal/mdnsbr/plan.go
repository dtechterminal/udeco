// SPDX-License-Identifier: GPL-2.0-or-later

package mdnsbr

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// Env is the unit as the planner needs it (the agent reads it from its
// snapshot, the saved system_cfg and /sys).
type Env struct {
	VAPs    map[string]string   // controller VAP devname (ra0, rai1) -> vif (wl02)
	Vifs    map[string]bool     // every Wi-Fi vif serving an SSID now
	Guest   map[string]bool     // vifs of guest SSIDs: never tapped, never sent to
	Bridges map[string][]string // local bridge (br-lan, br-v<vid>) -> its ports
	Uplink  string              // the uplink port, for VLANs without a bridge here ("" = none)
	MACs    [][6]byte           // the unit's interface MACs
}

// LocalBridge is the bridge bcmwifi builds for a VLAN (1 = untagged).
func LocalBridge(vlan int) string {
	if vlan <= 1 {
		return unit.LANBridge
	}
	return unit.VLANBridge(vlan)
}

// localVLAN is the VLAN of a local bridge name (ok false for other names:
// a VLAN bridge counts only as LocalBridge names it, for VLANs 2-4094).
func localVLAN(br string) (int, bool) {
	if br == unit.LANBridge {
		return 1, true
	}
	if v, ok := unit.ParseVLANBridge(br); ok && v >= 2 && v <= 4094 && unit.VLANBridge(v) == br {
		return v, true
	}
	return 0, false
}

// BuildPlan turns the controller's mdns_sd section into an engine plan for
// this unit. Filters on VAPs the unit does not serve, guest VAPs and
// VLANs it cannot reach are left out with a note (closed: nothing is
// forwarded for them).
func BuildPlan(c Config, env Env) (Plan, []string) {
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, "mdns bridge: "+fmt.Sprintf(f, a...)) }
	p := Plan{Own: map[string]*Policy{}, APMode: c.APMode, OwnMAC: env.MACs}
	if !c.Enabled {
		return Plan{}, nil
	}
	// the VLAN of every vif, from the bridge holding it
	vifVLAN := map[string]int{}
	for br, ports := range env.Bridges {
		v, ok := localVLAN(br)
		if !ok {
			continue
		}
		for _, x := range ports {
			if env.Vifs[x] {
				vifVLAN[x] = v
			}
		}
	}
	// proxies: dst VLAN -> src VLANs
	proxied := map[[2]int]bool{}
	for _, px := range c.Proxies {
		dv, ok := BridgeVLAN(px.Dst)
		if !ok {
			note("proxy destination %q is not a bridge name: ignored", px.Dst)
			continue
		}
		for _, s := range px.Srcs {
			sv, ok := BridgeVLAN(s)
			if !ok {
				note("proxy source %q is not a bridge name: ignored", s)
				continue
			}
			if sv != dv {
				proxied[[2]int{dv, sv}] = true
			}
		}
	}
	needVLAN := map[int]bool{} // VLANs all of whose ports are tapped
	dstVif := map[string]bool{}
	routes := map[[2]string]Route{}
	for i, f := range c.Filters {
		pol := NewPolicy(f)
		for _, d := range f.VAPs {
			vif, ok := env.VAPs[d]
			switch {
			case !ok || !env.Vifs[vif]:
				note("filter %d: VAP %s is not served here: skipped", i+1, d)
				continue
			case env.Guest[vif]:
				note("filter %d: VAP %s (%s) is a guest SSID: no mDNS is bridged to guests", i+1, d, vif)
				continue
			}
			vv, ok := vifVLAN[vif]
			if !ok {
				note("filter %d: %s is in no VLAN bridge: skipped", i+1, vif)
				continue
			}
			if f.VLAN == vv {
				if pol.All() {
					delete(p.Own, vif) // a later filter allows all: nothing to intercept
					continue
				}
				p.Own[vif] = pol // the last filter for a VAP and VLAN wins, as on a UAP
				needVLAN[vv] = true
				continue
			}
			if !proxied[[2]int{vv, f.VLAN}] {
				note("filter %d: no proxy brings VLAN %d to %s (VLAN %d): skipped", i+1, f.VLAN, d, vv)
				continue
			}
			routes[[2]string{vif, strconv.Itoa(f.VLAN)}] = Route{Vif: vif, SrcVLAN: f.VLAN, Policy: pol}
			dstVif[vif] = true
			needVLAN[f.VLAN] = true
		}
	}
	rk := make([][2]string, 0, len(routes))
	for k := range routes {
		rk = append(rk, k)
	}
	sort.Slice(rk, func(i, j int) bool { return rk[i][0]+"/"+rk[i][1] < rk[j][0]+"/"+rk[j][1] })
	for _, k := range rk {
		p.Routes = append(p.Routes, routes[k])
	}
	// ports
	seen := map[string]bool{}
	addPort := func(x Port) {
		if !seen[x.Key()] {
			seen[x.Key()] = true
			p.Ports = append(p.Ports, x)
		}
	}
	vlans := make([]int, 0, len(needVLAN))
	for v := range needVLAN {
		vlans = append(vlans, v)
	}
	sort.Ints(vlans)
	for _, v := range vlans {
		br := LocalBridge(v)
		ports, ok := env.Bridges[br]
		if !ok {
			switch {
			case c.APMode:
				note("VLAN %d has no bridge here and AP mode takes no wired mDNS: nothing to bridge from it", v)
			case env.Uplink == "" || !ifRE.MatchString(env.Uplink):
				note("VLAN %d has no bridge here and the uplink is not known: not bridged", v)
			default:
				addPort(Port{Name: env.Uplink, VID: v, VLAN: v})
			}
			continue
		}
		for _, x := range ports {
			switch {
			case !ifRE.MatchString(x), env.Guest[x]:
				continue
			case env.Vifs[x]:
				addPort(Port{Name: x, VLAN: v, Vif: true})
			case strings.HasPrefix(x, "wl"):
				continue // a Wi-Fi interface serving no SSID (TP-Link's backhaul vif)
			default:
				addPort(Port{Name: x, VLAN: v})
			}
		}
	}
	for _, vif := range sortedSet(dstVif) {
		addPort(Port{Name: vif, VLAN: vifVLAN[vif], Vif: true})
	}
	if len(p.Own) == 0 && len(p.Routes) == 0 {
		return Plan{}, notes
	}
	return p, notes
}
