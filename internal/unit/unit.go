// SPDX-License-Identifier: GPL-2.0-or-later

// Package unit holds the names the agent and the units it runs on agree
// on: the LAN bridge of each firmware, the VLAN bridges the agent builds
// and the directories the agent lives in. It imports nothing from this
// module, so any package may use it, and it is the one place these names
// are written down.
package unit

import "strconv"

// Where the agent lives on a unit. The deploy scripts and the launchers
// (deploy/deco-ap.sh, deploy/jio-ap.sh, deploy/jio-start.sh) run without
// this module and write the same paths out; cmd/udeco-ap's TestUnitLayout
// holds each of them to these constants.
const (
	// DecoDir is the agent's directory on a Deco (ubifs flash): the agent,
	// its launcher, its config and everything it keeps across a reboot.
	DecoDir = "/tp_data/udeco"
	// JioDir is that directory on the JioFiber JCOW414.
	JioDir = "/flash2/udeco"
	// RunDir is the agent's run directory on both (ramfs): its lock, PID
	// file and start log, and the Wi-Fi backend's run files.
	RunDir = "/tmp/udeco"
	// RAMDir is the launcher's directory on both (ramfs): the agent it
	// unpacks, agent.log and agent.pid. The agent writes nothing there.
	RAMDir = "/tmp/udeco-bin"

	// ConfigFile is the agent's config in DecoDir or JioDir. The agent
	// keeps its state in the directory of the config it is started with.
	ConfigFile = "udeco-ap.json"
	// Launcher is the script there that starts the agent: on a Deco the
	// one deploy/deco-ap.sh writes, on the JCOW414 deploy/jio-start.sh.
	Launcher = "start.sh"
	// StateSub is the directory there with the Wi-Fi backend's last-good
	// config.
	StateSub = "state"
)

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
