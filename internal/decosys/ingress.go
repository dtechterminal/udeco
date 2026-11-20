package decosys

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
)

// IngressChain is the inbound filter chain (R5). It is the first rule of
// INPUT, ahead of TP-Link's zone_lan, for IPv4 and IPv6.
const IngressChain = "UDECO-IN"

// DefaultSSHDPort is the agent's SSH-adopt port when Options.SSHDPort is 0.
const DefaultSSHDPort = 2222

// TP-Link's management listeners, dropped from every source (loopback
// excepted): TMP over SSH (dropbear :20001, the master's root path, B9),
// TDP (tmpsvr udp/tcp :20002, D9), uhttpd-fw (:20003) and the web UI with
// its Lua handlers (:80, :443). Their replies to the unit's own outbound
// connections never match: those land on ephemeral ports (32768-61000).
var (
	ingressTCP = []string{"20001", "20002", "20003", "80", "443"}
	ingressUDP = []string{"20002"}
)

// Ingress installs (on=true) or removes the inbound fence. It is idempotent
// like Egress, and it may run before the takeover: the agent installs it
// first thing at start (R1 phase 1), then re-asserts it every tick.
// Re-inserts are counted under "ingress" (Counts).
//
// Rules, in order (fall through to TP-Link's INPUT for the rest):
//  1. ACCEPT loopback;
//  2. DROP TP-Link's management ports, established sessions included (the
//     sessions the master or another TMP client already holds are cut);
//  3. ACCEPT ESTABLISHED,RELATED;
//  4. ACCEPT tcp/22 from MgmtSources, or from LANCIDR when MgmtSources is empty;
//  5. DROP tcp/22 from everyone else, only when MgmtSources is set;
//  6. ACCEPT tcp/SSHDPort from ConsoleIP (and, while SetSiteSSH(true),
//     from the IPv4 :22 sources), DROP it from everyone else (only when
//     ConsoleIP is set).
//
// It fails open: nothing is changed when the configuration does not parse,
// accepts are added before the drops they guard (a failed append leaves
// fewer drops, never a drop without its accept), and a missing iptables
// changes nothing. While a firmware upgrade is in flight the fence is left
// as it is (Guard.Upgrade).
func (m *Manager) Ingress(ctx context.Context, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ingress(ctx, on)
}

// ingress implements Ingress; callers hold m.mu.
func (m *Manager) ingress(ctx context.Context, on bool) error {
	v4 := m.bin("iptables")
	if !strings.HasPrefix(v4, "/") {
		return errors.New("ingress: iptables not found")
	}
	fams := []struct {
		bin string
		v6  bool
	}{{v4, false}}
	if v6 := m.bin("ip6tables"); strings.HasPrefix(v6, "/") {
		fams = append(fams, struct {
			bin string
			v6  bool
		}{v6, true})
	}
	if !on {
		var errs []error
		for _, f := range fams {
			errs = append(errs, m.chainOff(ctx, f.bin, "INPUT", IngressChain))
		}
		return errors.Join(errs...)
	}

	// All rules are built before anything changes.
	rules := make([][][]string, len(fams))
	for i, f := range fams {
		r, err := m.ingressRules(f.v6)
		if err != nil {
			return fmt.Errorf("ingress: %w", err)
		}
		rules[i] = r
	}
	procs, err := m.readProcs()
	if err != nil {
		return fmt.Errorf("ingress: read /proc: %w", err)
	}
	if g := m.guard(procs); len(g.Upgrade) > 0 {
		m.o.Logf("decosys: ingress: %s (%s): left unchanged", WarnUpgrade, strings.Join(g.Upgrade, "; "))
		return nil
	}
	var errs []error
	for i, f := range fams {
		repaired, err := m.syncChain(ctx, f.bin, IngressChain, rules[i])
		if err != nil {
			errs = append(errs, err)
			continue
		}
		moved, err := m.jumpFirst(ctx, f.bin, "INPUT", IngressChain, LockChain) // the login lock may lead
		if err != nil {
			errs = append(errs, err)
			continue
		}
		m.markInstalled("ingress", f.bin, IngressChain, rules[i], repaired || moved)
	}
	return errors.Join(errs...)
}

// ingressRules returns the rule specs for one family, in 'iptables -S' form.
func (m *Manager) ingressRules(v6 bool) ([][]string, error) {
	rules := [][]string{{"-i", "lo", "-j", "ACCEPT"}}
	for _, p := range ingressTCP {
		rules = append(rules, []string{"-p", "tcp", "-m", "tcp", "--dport", p, "-j", "DROP"})
	}
	for _, p := range ingressUDP {
		rules = append(rules, []string{"-p", "udp", "-m", "udp", "--dport", p, "-j", "DROP"})
	}
	rules = append(rules, []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})

	// SSH :22.
	srcs, err := mgmtSources(m.o.MgmtSources, v6)
	if err != nil {
		return nil, err
	}
	explicit := len(m.o.MgmtSources) > 0
	if !explicit && !v6 && m.o.LANCIDR != "" {
		_, lan, err := net.ParseCIDR(m.o.LANCIDR)
		if err != nil || lan.IP.To4() == nil {
			return nil, fmt.Errorf("bad LANCIDR %q", m.o.LANCIDR)
		}
		srcs = []string{lan.String()}
	}
	for _, s := range srcs {
		rules = append(rules, []string{"-s", s, "-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "ACCEPT"})
	}
	if explicit {
		rules = append(rules, []string{"-p", "tcp", "-m", "tcp", "--dport", "22", "-j", "DROP"})
	}

	// The agent's SSH-adopt listener: the console only (IPv4).
	if m.o.ConsoleIP != "" {
		ip := net.ParseIP(m.o.ConsoleIP).To4()
		if ip == nil {
			return nil, fmt.Errorf("bad ConsoleIP %q", m.o.ConsoleIP)
		}
		port := strconv.Itoa(m.o.SSHDPort)
		if !v6 {
			rules = append(rules, []string{"-s", ip.String() + "/32", "-p", "tcp", "-m", "tcp", "--dport", port, "-j", "ACCEPT"})
			rules = append(rules, m.siteSSHRules(srcs, ip.String()+"/32", port)...)
		}
		rules = append(rules, []string{"-p", "tcp", "-m", "tcp", "--dport", port, "-j", "DROP"})
	}
	return rules, nil
}

// mgmtSources parses MgmtSources and returns the CIDRs of one family, in the
// form iptables prints (a host gets /32 or /128). Any entry that does not
// parse is an error, so a typo never installs the :22 drop.
func mgmtSources(hosts []string, v6 bool) ([]string, error) {
	var out []string
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		var n *net.IPNet
		if strings.Contains(h, "/") {
			_, c, err := net.ParseCIDR(h)
			if err != nil {
				return nil, fmt.Errorf("bad management host %q", h)
			}
			n = c
		} else if ip := net.ParseIP(h); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		} else {
			return nil, fmt.Errorf("bad management host %q", h)
		}
		if (n.IP.To4() == nil) == v6 && !slices.Contains(out, n.String()) {
			out = append(out, n.String())
		}
	}
	return out, nil
}

// jumpFirst makes '-j chain' the first rule of parent, exactly once,
// behind only the jumps to the ahead chains that lead parent (UDECO-IN
// leaves the login lock ahead of it). A missing or misplaced jump is
// inserted before any stale copy is deleted (by number, bottom up), so the
// chain is never unhooked. It reports whether anything changed.
func (m *Manager) jumpFirst(ctx context.Context, bin, parent, chain string, ahead ...string) (bool, error) {
	return jumpFirst(ctx, m.o.Run, func(ctx context.Context, name string, args ...string) error {
		return m.mutate(ctx, name, args...)
	}, bin, []string{"-w"}, parent, chain, ahead...)
}

// jumpFirst is Manager.jumpFirst for any runner: pre goes before every
// command's arguments (-w or nothing), mutate runs the changes.
func jumpFirst(ctx context.Context, run Runner, mutate func(ctx context.Context, name string, args ...string) error,
	bin string, pre []string, parent, chain string, ahead ...string) (bool, error) {
	cmd := func(a ...string) []string { return append(slices.Clone(pre), a...) }
	out, err := run.Run(ctx, bin, cmd("-S", parent)...)
	if err != nil {
		return false, fmt.Errorf("%s -S %s: %w", bin, parent, err)
	}
	var pos []int
	n, lead := 0, 0
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 || f[0] != "-A" || f[1] != parent {
			continue
		}
		n++
		r := canonRule(f[2:])
		if r == "-j "+chain {
			pos = append(pos, n)
		} else if n == lead+1 && slices.ContainsFunc(ahead, func(c string) bool { return r == "-j "+c }) {
			lead++
		}
	}
	want := lead + 1
	if slices.Equal(pos, []int{want}) {
		return false, nil
	}
	if len(pos) > 0 && pos[0] == want {
		pos = pos[1:]
	} else {
		if err := mutate(ctx, bin, cmd("-I", parent, strconv.Itoa(want), "-j", chain)...); err != nil {
			return true, err
		}
		for i := range pos {
			pos[i]++
		}
	}
	for i := len(pos) - 1; i >= 0; i-- {
		if err := mutate(ctx, bin, cmd("-D", parent, strconv.Itoa(pos[i]))...); err != nil {
			return true, err
		}
	}
	return true, nil
}
