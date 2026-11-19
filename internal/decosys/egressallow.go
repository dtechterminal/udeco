// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"net"
	"slices"
	"strconv"
)

// SetEgressAllowTCP sets the extra TCP destinations ("ip:port", IPv4) the
// egress chain lets through: the RadSec servers the agent's proxy connects
// to (cmd/udeco-ap/radsec.go). Only destinations outside the LAN get a
// rule (the LAN is allowed anyway), each an exact address and port before
// the final DROP. Invalid entries are ignored. It reports whether the list
// changed; the next Egress(true) installs it.
func (m *Manager) SetEgressAllowTCP(dsts []string) bool {
	var norm []string
	for _, d := range dsts {
		h, p, err := net.SplitHostPort(d)
		ip := net.ParseIP(h).To4()
		port, perr := strconv.Atoi(p)
		if err != nil || ip == nil || perr != nil || port < 1 || port > 65535 {
			continue
		}
		norm = append(norm, net.JoinHostPort(ip.String(), strconv.Itoa(port)))
	}
	slices.Sort(norm)
	norm = slices.Compact(norm)
	m.mu.Lock()
	defer m.mu.Unlock()
	if slices.Equal(norm, m.allowTCP) {
		return false
	}
	m.allowTCP = norm
	return true
}

// allowTCPRules are the egress rules for allowTCP outside lan, in
// 'iptables -S' order (canonRule drops the implicit "-m tcp"); callers
// hold m.mu.
func (m *Manager) allowTCPRules(lan *net.IPNet) [][]string {
	var out [][]string
	for _, d := range m.allowTCP {
		h, p, _ := net.SplitHostPort(d)
		if ip := net.ParseIP(h); ip == nil || lan.Contains(ip) {
			continue
		}
		out = append(out, []string{"-d", h + "/32", "-p", "tcp", "--dport", p, "-j", "RETURN"})
	}
	return out
}
