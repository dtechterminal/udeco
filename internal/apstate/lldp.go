// SPDX-License-Identifier: GPL-2.0-or-later

package apstate

// LLDPNeighbor is one device heard on a port.
type LLDPNeighbor struct {
	Port                  string // local interface (lan1, wan, ...)
	ChassisID, ChassisDes string
	PortID, PortDescr     string
}
