package decosys

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
)

// EgressChain is the filter chain holding the egress policy. It is jumped
// to from the top of OUTPUT, so it sees only the unit's own traffic: client
// traffic is bridged and never reaches OUTPUT (no br_netfilter on this
// kernel).
const EgressChain = "UDECO-OUT"

// Egress turns the unit's own-traffic firewall on or off, for IPv4
// (iptables) and, when present, IPv6 (ip6tables). Both directions are
// idempotent: it reads the chain with -S and the jump with -C and only
// changes what differs. TP-Link's firewall leaves OUTPUT at ACCEPT, so
// allowed packets RETURN to it unchanged; the chain only ever drops.
//
// IPv4 allows loopback, ESTABLISHED/RELATED, LANCIDR (controller, gateway
// DHCP/DNS/NTP, SSH, syslog), the limited broadcast (DHCP, UniFi discovery)
// and multicast (UniFi discovery 233.89.188.1, mDNS, IGMP), plus the
// controller and gateway if they lie outside LANCIDR. Everything else is
// dropped, DNS to outside servers included.
//
// IPv6 allows loopback, ESTABLISHED/RELATED, link-local unicast, link-scope
// multicast and neighbour solicitation/advertisement to any address, and
// drops the rest: nothing on the LAN needs the unit's global IPv6.
func (m *Manager) Egress(ctx context.Context, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.egress(ctx, on)
}

// egress implements Egress; callers hold m.mu.
func (m *Manager) egress(ctx context.Context, on bool) error {
	type family struct {
		bin   string
		rules func() ([][]string, error)
	}
	v4 := m.bin("iptables")
	if !strings.HasPrefix(v4, "/") {
		return errors.New("egress: iptables not found")
	}
	fams := []family{{v4, m.rules4}}
	if v6 := m.bin("ip6tables"); strings.HasPrefix(v6, "/") {
		fams = append(fams, family{v6, m.rules6})
	}

	var errs []error
	for _, f := range fams {
		if !on {
			errs = append(errs, m.egressOff(ctx, f.bin))
			continue
		}
		rules, err := f.rules()
		if err != nil {
			return fmt.Errorf("egress: %w", err)
		}
		errs = append(errs, m.egressOn(ctx, f.bin, rules))
	}
	return errors.Join(errs...)
}

// egressOn makes the chain hold exactly rules and be jumped from OUTPUT.
func (m *Manager) egressOn(ctx context.Context, bin string, rules [][]string) error {
	repaired, err := m.syncChain(ctx, bin, EgressChain, rules)
	if err != nil {
		return err
	}
	if _, err := m.o.Run.Run(ctx, bin, "-w", "-C", "OUTPUT", "-j", EgressChain); err != nil {
		// First in OUTPUT, ahead of TP-Link's own ESTABLISHED and output rules.
		if err := m.mutate(ctx, bin, "-w", "-I", "OUTPUT", "1", "-j", EgressChain); err != nil {
			return err
		}
		repaired = true
	}
	m.markInstalled("egress", bin, EgressChain, rules, repaired)
	return nil
}

// markInstalled records that a chain holds rules; a repair of a chain this
// Manager had installed with the same rules is counted as a re-insert
// (R10g) under kind.
func (m *Manager) markInstalled(kind, bin, chain string, rules [][]string, repaired bool) {
	if m.o.DryRun {
		return
	}
	key := bin + " " + chain
	var sig []string
	for _, r := range rules {
		sig = append(sig, canonRule(r))
	}
	cur := strings.Join(sig, "\n")
	if prev, ok := m.installed[key]; repaired && ok && prev == cur {
		m.counts[kind]++
		m.o.Logf("decosys: ALERT: %s chain %s (%s) had to be re-inserted", kind, chain, bin)
	}
	m.installed[key] = cur
}

// syncChain makes chain exist and hold exactly rules, in order. It reports
// whether an existing chain had to be created or rewritten. The rules are
// appended in order and the first failure stops the rest, so a chain whose
// accepts precede its drops fails open.
func (m *Manager) syncChain(ctx context.Context, bin, chain string, rules [][]string) (bool, error) {
	out, err := m.o.Run.Run(ctx, bin, "-w", "-S", chain)
	if err != nil {
		if err := m.mutate(ctx, bin, "-w", "-N", chain); err != nil {
			return false, err
		}
		out = nil
	}
	if out != nil && sameRules(out, chain, rules) {
		return false, nil
	}
	if out != nil {
		if err := m.mutate(ctx, bin, "-w", "-F", chain); err != nil {
			return true, err
		}
	}
	for _, r := range rules {
		if err := m.mutate(ctx, bin, append([]string{"-w", "-A", chain}, r...)...); err != nil {
			return true, err
		}
	}
	return true, nil
}

// egressOff removes every jump to the chain, then the chain itself.
func (m *Manager) egressOff(ctx context.Context, bin string) error {
	return m.chainOff(ctx, bin, "OUTPUT", EgressChain)
}

// chainOff removes every jump from parent to chain, then the chain.
func (m *Manager) chainOff(ctx context.Context, bin, parent, chain string) error {
	delete(m.installed, bin+" "+chain)
	for range 8 { // a duplicated jump is removed one per -D
		if _, err := m.o.Run.Run(ctx, bin, "-w", "-C", parent, "-j", chain); err != nil {
			break
		}
		if err := m.mutate(ctx, bin, "-w", "-D", parent, "-j", chain); err != nil {
			return err
		}
		if m.o.DryRun {
			break
		}
	}
	if _, err := m.o.Run.Run(ctx, bin, "-w", "-S", chain); err != nil {
		return nil // no chain
	}
	if err := m.mutate(ctx, bin, "-w", "-F", chain); err != nil {
		return err
	}
	return m.mutate(ctx, bin, "-w", "-X", chain)
}

// rules4 returns the IPv4 rule specs, in 'iptables -S' form after the chain.
func (m *Manager) rules4() ([][]string, error) {
	if m.o.LANCIDR == "" {
		return nil, errors.New("LANCIDR is required: refusing to drop egress without a LAN allow rule")
	}
	_, lan, err := net.ParseCIDR(m.o.LANCIDR)
	if err != nil || lan.IP.To4() == nil {
		return nil, fmt.Errorf("bad LANCIDR %q", m.o.LANCIDR)
	}
	rules := [][]string{
		{"-o", "lo", "-j", "RETURN"},
		{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"},
		{"-d", lan.String(), "-j", "RETURN"},
		{"-d", "255.255.255.255/32", "-j", "RETURN"},
		{"-d", "224.0.0.0/4", "-j", "RETURN"},
	}
	for _, h := range []string{m.o.ControllerIP, m.o.GatewayIP} {
		ip := net.ParseIP(h).To4()
		if h == "" || ip == nil || lan.Contains(ip) {
			continue
		}
		r := []string{"-d", ip.String() + "/32", "-j", "RETURN"}
		if !slices.ContainsFunc(rules, func(x []string) bool { return slices.Equal(x, r) }) {
			rules = append(rules, r)
		}
	}
	rules = append(rules, m.allowTCPRules(lan)...) // RadSec servers: egressallow.go
	return append(rules, []string{"-j", "DROP"}), nil
}

// rules6 returns the IPv6 rule specs.
func (m *Manager) rules6() ([][]string, error) {
	return [][]string{
		{"-o", "lo", "-j", "RETURN"},
		{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "RETURN"},
		{"-d", "fe80::/10", "-j", "RETURN"},
		{"-d", "ff02::/16", "-j", "RETURN"},
		{"-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", "135", "-j", "RETURN"},
		{"-p", "ipv6-icmp", "-m", "icmp6", "--icmpv6-type", "136", "-j", "RETURN"},
		{"-j", "DROP"},
	}, nil
}

// sameRules reports whether 'iptables -S <chain>' output holds exactly rules,
// in order. Formatting differences iptables introduces (an implicit
// "-m icmp6"/"-m tcp" after -p, "icmpv6" for "ipv6-icmp") are normalised so
// that a correct chain is not rewritten on every call.
func sameRules(out []byte, chain string, rules [][]string) bool {
	if out == nil {
		return false
	}
	var have []string
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) >= 2 && f[0] == "-A" && f[1] == chain {
			have = append(have, canonRule(f[2:]))
		}
	}
	if len(have) != len(rules) {
		return false
	}
	for i, r := range rules {
		if have[i] != canonRule(r) {
			return false
		}
	}
	return true
}

// canonRule normalises one rule spec for comparison.
func canonRule(f []string) string {
	var out []string
	for i := 0; i < len(f); i++ {
		switch {
		case f[i] == "-m" && i+1 < len(f) && slices.Contains([]string{"icmp", "icmp6", "tcp", "udp"}, f[i+1]):
			i++
		case i > 0 && f[i-1] == "-p" && (f[i] == "icmpv6" || f[i] == "58"):
			out = append(out, "ipv6-icmp")
		case f[i] == "-m" && i+2 < len(f) && f[i+1] == "state" && f[i+2] == "--state":
			// the state match lists as itself on some firmware and as
			// conntrack on others: the same rule either way
			out = append(out, "-m", "conntrack", "--ctstate")
			i += 2
		default:
			out = append(out, f[i])
		}
	}
	return strings.Join(out, " ")
}
