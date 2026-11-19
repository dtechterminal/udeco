package decosys

import "context"

// LAN is what the agent learns from reading the unit: the gateway, the
// unit's subnet and its own lease. It is unknown in R1 phase 1, when the
// inbound fence goes in before the unit is read, and it changes with a new
// lease.
type LAN struct {
	GatewayIP string // Options.GatewayIP
	LANCIDR   string // Options.LANCIDR
	UnitIP    string // Options.UnitIP
}

// SetLAN replaces GatewayIP, LANCIDR and UnitIP. It changes nothing on the
// unit by itself: the next Enforce, Egress or Ingress uses the new values,
// and a firewall rule set that changes with them is rewritten without being
// counted as a re-insert. It reports whether anything changed.
func (m *Manager) SetLAN(l LAN) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.o.GatewayIP == l.GatewayIP && m.o.LANCIDR == l.LANCIDR && m.o.UnitIP == l.UnitIP {
		return false
	}
	m.o.GatewayIP, m.o.LANCIDR, m.o.UnitIP = l.GatewayIP, l.LANCIDR, l.UnitIP
	return true
}

// InFlight is Guard for a unit that has no Manager yet: what is in flight
// under root now, read from /proc and the upgrade marker files only (it runs
// no command). The agent's boot gate (R1) uses it in both modes, so it and
// Enforce share one definition of "upgrade in flight" (R17).
func InFlight(root string) (Guard, error) {
	return New(Options{Root: root}).Guard(context.Background())
}
