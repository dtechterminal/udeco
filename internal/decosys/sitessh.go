// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

// SetSiteSSH opens (on) or closes the agent's SSH port to the site's device
// users: while on, the inbound fence also accepts SSHDPort from the IPv4
// sources that may reach :22 (MgmtSources, or LANCIDR without them); the
// console's own rule and the final DROP stay, and IPv6 stays dropped. The
// agent's SSH server checks every login itself (internal/device
// sitessh.go); this only keeps the port shut while site logins are off.
// It reports whether the setting changed; the next Ingress(true) installs
// it.
func (m *Manager) SetSiteSSH(on bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.siteSSH == on {
		return false
	}
	m.siteSSH = on
	return true
}

// siteSSHRules are the IPv4 accepts for SSHDPort from srcs (the :22
// sources) while site logins are on; callers hold m.mu.
func (m *Manager) siteSSHRules(srcs []string, console, port string) [][]string {
	if !m.siteSSH {
		return nil
	}
	var out [][]string
	for _, s := range srcs {
		if s != console {
			out = append(out, []string{"-s", s, "-p", "tcp", "-m", "tcp", "--dport", port, "-j", "ACCEPT"})
		}
	}
	return out
}
