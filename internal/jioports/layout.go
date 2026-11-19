// SPDX-License-Identifier: GPL-2.0-or-later

// Package jioports shows the JioFiber JCOW414's four switch ports in UniFi
// as the ports of a UAP-IW-HD (UHDIW, the in-wall AP with four front ports
// and a rear uplink) and applies the controller's per-port VLANs to them.
//
// The unit (verified read-only on the Garage AP, 2026-11-19):
//
//   - each switch port is a netdev eth0.P (P = the port's label, 1-4; the
//     switch's port P, per /proc/tc3162/eth_portmap's lan_port_map); its
//     carrier and speed files say nothing (carrier 1, speed EINVAL), the
//     link state is in /proc/tc3162/gsw_link_st;
//   - untagged frames of port P arrive tagged VLAN 1 on the 802.1Q device
//     eth0.P.1 (/proc/net/vlan/config), the LAN bridge bdg2's member; a frame
//     tagged N arrives on eth0.P.N once that device exists (verified on the
//     uplink, port 4, where the agent's VLAN SSIDs use eth0.4.N);
//   - port 4 is the uplink to the gateway, port 1 feeds the tenant's router,
//     ports 2 and 3 have never carried traffic.
//
// UniFi numbering (the UHDIW's, from the controller's model table: five
// ports, the rear "PoE In + Data" jack last): ports 1-3 are the unit's
// ports 1-3, UniFi port 4 does not exist on the unit (reported down and not
// editable), UniFi port 5 is the unit's port 4, the uplink.
package jioports

import "strconv"

const (
	// UplinkPhys is the unit's uplink port; it is never changed beyond
	// the VLAN devices the VLAN SSIDs already put on it.
	UplinkPhys = 4
	// UplinkIdx is the uplink's UniFi port index (the UHDIW's rear jack).
	UplinkIdx = 5
	// MissingIdx is the UHDIW front port the unit does not have.
	MissingIdx = 4
	// NumPorts is the UHDIW's port count (if_table num_port).
	NumPorts = 5
)

// LANPorts are the unit's ports whose VLANs the controller may set.
var LANPorts = []int{1, 2, 3}

// Idx is the UniFi port index of the unit's port phys (0 = none).
func Idx(phys int) int {
	switch {
	case phys == UplinkPhys:
		return UplinkIdx
	case phys >= 1 && phys <= 3:
		return phys
	}
	return 0
}

// Phys is the unit's port behind UniFi port idx (0 = none: port 4).
func Phys(idx int) int {
	switch {
	case idx == UplinkIdx:
		return UplinkPhys
	case idx >= 1 && idx <= 3:
		return idx
	}
	return 0
}

// Parent is port phys's switch netdev (eth0.P).
func Parent(phys int) string { return "eth0." + strconv.Itoa(phys) }

// Untagged is port phys's untagged device (eth0.P.1).
func Untagged(phys int) string { return Parent(phys) + ".1" }
