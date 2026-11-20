// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"fmt"
	"net"
	"strconv"
)

// AnnounceStation sends a gratuitous ARP for a station that just
// associated (the agent knows its address: the unit's ARP table, or what
// the proxy ARP responder learnt), from the station's MAC, out of the
// uplink port of its BSS's network (a VLAN SSID's: the uplink's VLAN
// device), as a U6 does after a roam: the switches move the station's MAC
// to this port and the LAN's ARP caches are refreshed at once. Not sent on
// the air (the station's own BSS has it already).
func (a *Applier) AnnounceStation(ctx context.Context, vif, mac string, ip net.IP) error {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return fmt.Errorf("mtkwifi: GARP: bad MAC %q", mac)
	}
	v4 := ip.To4()
	if v4 == nil || v4.Equal(net.IPv4zero) {
		return fmt.Errorf("mtkwifi: GARP: %s is not an IPv4 address", ip)
	}
	a.mu.Lock()
	vlan, ok := -1, false
	for _, rd := range a.o.Layout {
		rp := a.live[rd.Band]
		for i, b := range rp.BSS {
			if a.ifaceOf(rd, rp, i) == vif {
				vlan, ok = b.VLAN, true
			}
		}
	}
	dev := a.uplink
	if ok && vlan > 0 {
		parent, err := a.vlanParent()
		if err != nil {
			a.mu.Unlock()
			return err
		}
		dev = parent + "." + strconv.Itoa(vlan)
	}
	dry := a.o.DryRun
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("mtkwifi: GARP: %s serves no SSID", vif)
	}
	if dev == "" {
		return fmt.Errorf("mtkwifi: GARP: no uplink port known")
	}
	if dry {
		a.o.Logf("mtkwifi: dry run: GARP %s is at %s on %s", v4, hw, dev)
		return nil
	}
	return a.o.sendFrame(dev, garp(hw, v4))
}
