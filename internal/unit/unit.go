// SPDX-License-Identifier: GPL-2.0-or-later

// Package unit holds the names the agent and the units it runs on agree
// on: the LAN bridge of each firmware and the VLAN bridges the agent
// builds. It imports nothing from this module, so any package may use it,
// and it is the one place these names are written down.
package unit

import "strconv"

const (
	// LANBridge is the bridge the Deco's LAN, ports and untagged Wi-Fi
	// networks are in (TP-Link's own).
	LANBridge = "br-lan"
	// JioLANBridge is the JioFiber JCOW414's LAN bridge (the vendor's own).
	JioLANBridge = "bdg2"
	// VLANBridgePrefix starts the name of every VLAN bridge the agent
	// builds: br-v<vid>.
	VLANBridgePrefix = "br-v"
)

// VLANBridge names the bridge the agent builds for VLAN vid: br-v<vid>.
func VLANBridge(vid int) string { return VLANBridgePrefix + strconv.Itoa(vid) }

// ParseVLANBridge reads a VLAN bridge's name: VLANBridgePrefix and decimal
// digits, nothing else. It checks neither the VLAN range nor leading
// zeros (so VLANBridge(vid) need not be name); a caller with a range has
// its own check.
func ParseVLANBridge(name string) (vid int, ok bool) {
	if len(name) <= len(VLANBridgePrefix) || name[:len(VLANBridgePrefix)] != VLANBridgePrefix {
		return 0, false
	}
	digits := name[len(VLANBridgePrefix):]
	for i := 0; i < len(digits); i++ {
		if digits[i] < '0' || digits[i] > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(digits)
	if err != nil {
		return 0, false
	}
	return v, true
}
