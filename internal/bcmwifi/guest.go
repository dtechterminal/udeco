// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
)

// Guest isolation with ebtables (docs/deco/device-capabilities.md).
//
// The X20 kernel has the ebtables filter table with the ip, ip6 and MAC
// matches, but no among, arp, pkttype, limit, log, redirect or dnat, and no
// br_netfilter (iptables never sees bridged frames). ebtables is v2.0.10-4.
// So, for every vif that carries a guest SSID:
//
//	FORWARD -i <vif> -j UDECO-GIN    frames from guests (to the LAN/uplink)
//	INPUT   -i <vif> -j UDECO-GIN    frames from guests to the AP itself
//	FORWARD -o <vif> -j UDECO-GOUT   frames to guests (from any other port)
//
// UDECO-GIN, policy DROP, in order:
//  1. EAPOL and ARP pass (ARP cannot be matched further: no --arp-*);
//  2. DHCP (udp 68 -> 67) passes;
//  3. DNS (udp/tcp 53) to the configured resolvers passes;
//  4. router advertisements and redirects (from a guest, to anyone) and
//     multicast neighbour advertisements are dropped: a guest must not
//     become the LAN's IPv6 router or rewrite LAN hosts' neighbour caches
//     (the ND counterpart of ARP spoofing; unlike ARP, it can be matched);
//     the rest of IPv6 neighbour discovery and DHCPv6 to multicast pass;
//  5. the portal allow-list (guest_pre_allow) passes, to any MAC;
//  6. with the portal on: the portal host's ports (device.PortalHostPorts) pass,
//     then UDECO-GAUTH (policy DROP; one "-s <mac> -j RETURN" per authorised
//     guest, since among is missing) drops every unauthorised guest;
//  7. anything not addressed to the gateway's MAC is dropped: no LAN host,
//     no guest on another AP (cross-AP isolation, together with UDECO-GOUT);
//  8. the gateway's IP passes; the restricted ranges (guest_restricted,
//     always with RFC 1918, link-local and multicast) and IPv6 ULA
//     (fc00::/7) are dropped; the rest (the internet, via the gateway) passes.
//
// UDECO-GOUT, policy DROP: frames from the gateway's MAC, ARP, and replies
// from the pre-allowed, portal and DNS addresses pass; nothing else reaches a
// guest (no other LAN host, no guest on another AP or SSID).
//
// The chains are built with policy DROP before they are filled, so a guest
// vif is never unrestricted while the rules change. Same-BSS isolation stays
// the driver's ap_isolate (SSID.Isolation). There is no captive-portal
// redirect: ebtables has no redirect/dnat target here, so with the portal on,
// unauthorised guests can only reach DHCP, DNS, the allow-list and the portal
// host until AuthorizeGuest.
//
// Assumptions (not verifiable without changing the unit): the listing format
// of `ebtables -L` (rules printed as their arguments, MACs maybe without
// leading zeros), user-chain policies (`-P <chain> DROP`) and the
// intrapositioned negation `-d ! <mac>` documented in this build's help.

// GuestPolicy is what guest isolation needs. The agent fills it from
// translate.GuestPolicy (Restricted, PreAllow, Portal, PortalHost) and from
// the collector (GatewayMAC, GatewayIP, DNS).
type GuestPolicy struct {
	GatewayMAC string   // the only L2 peer guests may reach (required)
	GatewayIP  string   // IPv4 (required)
	DNS        []string // IPv4 resolvers guests may query; empty = GatewayIP
	Restricted []string // IPv4 prefixes guests may not reach (always also RFC 1918, 169.254/16, 224/4)
	PreAllow   []string // IPv4 prefixes or addresses guests may reach anyway (the portal allow-list)
	Portal     bool     // only authorised guests (AuthorizeGuest) get past DHCP, DNS, PreAllow and the portal
	PortalHost string   // IPv4 of the portal (the controller); a host name is not resolved
}

// The guest ebtables chains, for every applier that isolates guests with
// them (here and mtkwifi): frames from a guest vif (GuestChainIn), frames
// to one (GuestChainOut), and the authorised guests of a portal
// (GuestChainAuth). GuestJumps sends a vif's frames to them.
const (
	GuestChainIn   = guestChainPrefix + "IN"   // UDECO-GIN
	GuestChainOut  = guestChainPrefix + "OUT"  // UDECO-GOUT
	GuestChainAuth = guestChainPrefix + "AUTH" // UDECO-GAUTH

	// guestChainPrefix starts every guest chain's name: a jump to a chain
	// so named is one of ours (parseEbJumps), whichever chain it is.
	guestChainPrefix = "UDECO-G"
)

var ourChains = []string{GuestChainIn, GuestChainOut, GuestChainAuth}

// defaultRestricted is always blocked for guests (RFC 1918, link-local,
// multicast), whatever the controller's guest_restricted holds.
var defaultRestricted = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "224.0.0.0/4"}

// portalPorts are the controller's guest portal ports
// (device.PortalHostPorts) as --ip-dport takes them: "8880:8882", "8843".
var portalPorts = portRanges(device.PortalHostPorts())

// portRanges writes ports for ebtables' --ip-dport: consecutive ports as
// one "first:last" range, any other port alone, each where the list first
// names one of its ports.
func portRanges(ports []int) []string {
	listed, done := map[int]bool{}, map[int]bool{}
	for _, p := range ports {
		listed[p] = true
	}
	var out []string
	for _, p := range ports {
		if done[p] {
			continue
		}
		lo, hi := p, p
		for listed[lo-1] {
			lo--
		}
		for listed[hi+1] {
			hi++
		}
		for q := lo; q <= hi; q++ {
			done[q] = true
		}
		r := strconv.Itoa(lo)
		if hi > lo {
			r += ":" + strconv.Itoa(hi)
		}
		out = append(out, r)
	}
	return out
}

// guestRules is a validated GuestPolicy.
type guestRules struct {
	GwMAC, GwIP string
	DNS         []string
	Restricted  []string
	PreAllow    []string
	Portal      bool
	PortalHost  string // "" = portal on but host unusable: nothing opened for it
}

// normalizeGuest validates g. It returns nil (with a note) when g cannot
// isolate guests: no policy, or no valid gateway MAC/IP. Bad list entries are
// dropped with a note; the default restricted ranges always stay.
func normalizeGuest(g *GuestPolicy) (*guestRules, []string) {
	if g == nil {
		return nil, nil
	}
	var notes []string
	note := func(f string, args ...any) { notes = append(notes, "guest policy: "+fmt.Sprintf(f, args...)) }
	r := &guestRules{GwMAC: normMAC(g.GatewayMAC), Portal: g.Portal}
	if ip, err := netip.ParseAddr(strings.TrimSpace(g.GatewayIP)); err == nil && ip.Is4() {
		r.GwIP = ip.String()
	}
	if r.GwMAC == "" || r.GwIP == "" {
		note("gateway MAC %q / IP %q not usable: guest SSIDs not served", g.GatewayMAC, g.GatewayIP)
		return nil, notes
	}
	v4 := func(kind string, vs []string, prefixOK bool) []string {
		var out []string
		seen := map[string]bool{}
		for _, v := range vs {
			v = strings.TrimSpace(v)
			var s string
			if p, err := netip.ParsePrefix(v); err == nil && prefixOK && p.Addr().Is4() {
				s = p.Masked().String()
			} else if a, err := netip.ParseAddr(v); err == nil && a.Is4() {
				s = a.String()
			} else {
				note("%s entry %q is not an IPv4 %s, ignored", kind, v, map[bool]string{true: "prefix or address", false: "address"}[prefixOK])
				continue
			}
			if !seen[s] {
				seen[s] = true
				out = append(out, s)
			}
		}
		return out
	}
	r.DNS = v4("DNS", g.DNS, false)
	if len(r.DNS) == 0 {
		r.DNS = []string{r.GwIP}
	}
	r.Restricted = v4("restricted", append(append([]string{}, defaultRestricted...), g.Restricted...), true)
	r.PreAllow = v4("pre-allow", g.PreAllow, true)
	if g.Portal {
		if a, err := netip.ParseAddr(strings.TrimSpace(g.PortalHost)); err == nil && a.Is4() {
			r.PortalHost = a.String()
		} else {
			note("portal host %q is not an IPv4 address: its ports are not opened (unauthorised guests reach only DHCP, DNS and the allow-list)", g.PortalHost)
		}
	}
	return r, notes
}

// render returns the rules of UDECO-GIN and UDECO-GOUT (ebtables arguments
// after "-A <chain>").
func (r *guestRules) render() (in, out [][]string) {
	add := func(rule ...string) { in = append(in, rule) }
	add("-p", "0x888e", "-j", "ACCEPT")
	add("-p", "ARP", "-j", "ACCEPT")
	add("-p", "IPv4", "--ip-proto", "udp", "--ip-sport", "68", "--ip-dport", "67", "-j", "ACCEPT")
	for _, d := range r.DNS {
		for _, p := range []string{"udp", "tcp"} {
			add("-p", "IPv4", "--ip-dst", d, "--ip-proto", p, "--ip-dport", "53", "-j", "ACCEPT")
		}
	}
	add("-p", "IPv6", "--ip6-proto", "58", "--ip6-icmp-type", "router-advertisement", "-j", "DROP")
	add("-p", "IPv6", "--ip6-proto", "58", "--ip6-icmp-type", "redirect", "-j", "DROP")
	add("-p", "IPv6", "-d", "Multicast", "--ip6-proto", "58", "--ip6-icmp-type", "neighbour-advertisement", "-j", "DROP")
	add("-p", "IPv6", "-d", "Multicast", "--ip6-proto", "58", "-j", "ACCEPT")
	add("-p", "IPv6", "-d", "Multicast", "--ip6-proto", "udp", "--ip6-dport", "547", "-j", "ACCEPT")
	for _, p := range r.PreAllow {
		add("-p", "IPv4", "--ip-dst", p, "-j", "ACCEPT")
	}
	if r.Portal {
		if r.PortalHost != "" {
			for _, port := range portalPorts {
				add("-p", "IPv4", "--ip-dst", r.PortalHost, "--ip-proto", "tcp", "--ip-dport", port, "-j", "ACCEPT")
			}
		}
		add("-j", GuestChainAuth)
	}
	add("-d", "!", r.GwMAC, "-j", "DROP")
	add("-p", "IPv4", "--ip-dst", r.GwIP, "-j", "ACCEPT")
	for _, p := range r.Restricted {
		add("-p", "IPv4", "--ip-dst", p, "-j", "DROP")
	}
	add("-p", "IPv6", "--ip6-dst", "fc00::/7", "-j", "DROP")
	add("-j", "ACCEPT")

	out = append(out, []string{"-s", r.GwMAC, "-j", "ACCEPT"}, []string{"-p", "ARP", "-j", "ACCEPT"})
	srcs := append(append([]string{}, r.PreAllow...), r.DNS...)
	if r.Portal && r.PortalHost != "" {
		srcs = append(srcs, r.PortalHost)
	}
	seen := map[string]bool{}
	for _, s := range srcs {
		if !seen[s] {
			seen[s] = true
			out = append(out, []string{"-p", "IPv4", "--ip-src", s, "-j", "ACCEPT"})
		}
	}
	return in, out
}

// ebJump is a rule in a built-in chain that jumps to one of ours.
type ebJump struct {
	Chain  string // FORWARD or INPUT
	Dir    string // -i or -o
	Vif    string
	Target string
}

// rule is j as ebtables arguments after the operation.
func (j ebJump) rule() []string { return []string{j.Chain, j.Dir, j.Vif, "-j", j.Target} }

func (j ebJump) args(op string) []string {
	return append([]string{"ebtables", op}, j.rule()...)
}

// vifJumps are the jumps that put vif behind the guest chains: what it
// sends, forwarded or to the unit itself, and what is forwarded to it.
func vifJumps(vif string) []ebJump {
	return []ebJump{
		{"FORWARD", "-i", vif, GuestChainIn},
		{"FORWARD", "-o", vif, GuestChainOut},
		{"INPUT", "-i", vif, GuestChainIn},
	}
}

// GuestJumps are the rules that put vif behind the guest chains, each as
// ebtables arguments after the operation: built-in chain, direction, vif,
// "-j", guest chain ("FORWARD -i <vif> -j UDECO-GIN", ...).
func GuestJumps(vif string) [][]string {
	var out [][]string
	for _, j := range vifJumps(vif) {
		out = append(out, j.rule())
	}
	return out
}

// guestLive is the live ebtables state of the agent's chains.
type guestLive struct {
	Chains map[string]bool // our chains that exist
	Jumps  []ebJump        // jumps to our chains in FORWARD and INPUT
	State  string          // RunDir/guest-ebtables.txt: what was last built
	Auth   []string        // MACs in UDECO-GAUTH
}

func (a *Applier) guestStatePath() string { return path.Join(a.o.RunDir, "guest-ebtables.txt") }
func (a *Applier) guestAuthPath() string  { return path.Join(a.o.RunDir, "guest-auth.txt") }

// readGuest lists the agent's ebtables chains and jumps (read-only).
func (a *Applier) readGuest(ctx context.Context) guestLive {
	g := guestLive{Chains: map[string]bool{}}
	for _, c := range ourChains {
		out, err := a.o.Run.Run(ctx, "ebtables", "-L", c)
		if err != nil {
			continue
		}
		g.Chains[c] = true
		if c == GuestChainAuth {
			g.Auth = parseEbMACs(string(out))
		}
	}
	for _, c := range []string{"FORWARD", "INPUT"} {
		out, err := a.o.Run.Run(ctx, "ebtables", "-L", c)
		if err != nil {
			continue
		}
		g.Jumps = append(g.Jumps, parseEbJumps(c, string(out))...)
	}
	if b, err := a.readFile(a.guestStatePath()); err == nil {
		g.State = string(b)
	}
	return g
}

func (g guestLive) any() bool { return len(g.Chains) > 0 || len(g.Jumps) > 0 || g.State != "" }

// parseEbJumps finds "-i|-o <vif> ... -j UDECO-*" rules in an ebtables -L
// listing of chain.
func parseEbJumps(chain, out string) []ebJump {
	var js []ebJump
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		var j ebJump
		for i := 0; i+1 < len(f); i++ {
			switch f[i] {
			case "-i", "-o", "--in-if", "--out-if":
				j.Dir, j.Vif = f[i][:2], f[i+1]
				if j.Dir == "--" {
					j.Dir = map[string]string{"--in-if": "-i", "--out-if": "-o"}[f[i]]
				}
			case "-j":
				j.Target = f[i+1]
			}
		}
		if j.Vif != "" && strings.HasPrefix(j.Target, guestChainPrefix) {
			j.Chain = chain
			js = append(js, j)
		}
	}
	return js
}

// parseEbMACs reads the "-s <mac>" of each rule in a listing. ebtables may
// print MACs without leading zeros (0:1a:...).
func parseEbMACs(out string) []string {
	var macs []string
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "-s" || f[i] == "--src" {
				if m := lenientMAC(f[i+1]); m != "" {
					macs = append(macs, m)
				}
			}
		}
	}
	sort.Strings(macs)
	return macs
}

func lenientMAC(s string) string {
	p := strings.Split(s, ":")
	if len(p) != 6 {
		return ""
	}
	var b strings.Builder
	for i, x := range p {
		v, err := strconv.ParseUint(x, 16, 8)
		if err != nil || len(x) == 0 || len(x) > 2 {
			return ""
		}
		if i > 0 {
			b.WriteByte(':')
		}
		fmt.Fprintf(&b, "%02x", v)
	}
	return b.String()
}

// guestState is the text kept in RunDir/guest-ebtables.txt: the rules and
// the vifs they guard, so a change in either rebuilds the chains.
func guestState(r *guestRules, vifs []string) string {
	in, out := r.render()
	var b strings.Builder
	fmt.Fprintf(&b, "vifs %s\nportal %t\n", strings.Join(vifs, " "), r.Portal)
	for _, x := range in {
		fmt.Fprintf(&b, "in %s\n", strings.Join(x, " "))
	}
	for _, x := range out {
		fmt.Fprintf(&b, "out %s\n", strings.Join(x, " "))
	}
	return b.String()
}

func wantJumps(vifs []string) []ebJump {
	var js []ebJump
	for _, v := range vifs {
		js = append(js, vifJumps(v)...)
	}
	return js
}

func hasJump(js []ebJump, j ebJump) bool {
	for _, x := range js {
		if x == j {
			return true
		}
	}
	return false
}

// guestSteps brings the ebtables guest chains to r on vifs (removing them
// when vifs is empty). foreign lists what was found wrong. The steps run
// before any BSS comes up, so a guest SSID never beacons unrestricted.
func (a *Applier) guestSteps(r *guestRules, vifs []string, g guestLive) (st []Step, foreign []string) {
	eb := func(desc string, args ...string) Step { return cmdStep(desc, append([]string{"ebtables"}, args...)...) }
	if r == nil || len(vifs) == 0 {
		if !g.any() {
			return nil, nil
		}
		for _, j := range g.Jumps {
			st = append(st, optStep("remove guest jump", j.args("-D")...))
		}
		for _, c := range ourChains {
			if g.Chains[c] {
				st = append(st, optStep("flush "+c, "ebtables", "-F", c))
			}
		}
		for _, c := range ourChains {
			if g.Chains[c] {
				st = append(st, optStep("delete "+c, "ebtables", "-X", c))
			}
		}
		return append(st, Step{Kind: StepRemove, Desc: "remove guest state", Path: a.guestStatePath(), Optional: true}), nil
	}
	state := guestState(r, vifs)
	chains := []string{GuestChainIn, GuestChainOut}
	if r.Portal {
		chains = append(chains, GuestChainAuth)
	}
	rebuild := g.State != state
	for _, c := range chains {
		if !g.Chains[c] {
			rebuild = true
			if g.State != "" {
				foreign = append(foreign, "ebtables chain "+c+" missing (removed by something else), rebuilt")
			}
		}
	}
	want := wantJumps(vifs)
	var missing, stale []ebJump
	for _, j := range want {
		if !hasJump(g.Jumps, j) {
			missing = append(missing, j)
		}
	}
	for _, j := range g.Jumps {
		if !hasJump(want, j) {
			stale = append(stale, j)
		}
	}
	if !rebuild && len(missing) == 0 && len(stale) == 0 {
		return nil, foreign
	}
	if g.State == state && len(missing) > 0 {
		foreign = append(foreign, fmt.Sprintf("%d guest ebtables jumps missing, re-added", len(missing)))
	}
	// Chains first, policy DROP: a jump to an empty chain drops everything.
	for _, c := range chains {
		if !g.Chains[c] {
			st = append(st, eb("create "+c, "-N", c))
		}
		st = append(st, eb("fail closed: "+c+" policy DROP", "-P", c, "DROP"))
	}
	for _, j := range missing {
		st = append(st, cmdStep("guest jump "+j.Dir+" "+j.Vif, "ebtables", "-I", j.Chain, "1", j.Dir, j.Vif, "-j", j.Target))
	}
	if rebuild {
		in, out := r.render()
		st = append(st, eb("flush "+GuestChainIn, "-F", GuestChainIn), eb("flush "+GuestChainOut, "-F", GuestChainOut))
		if r.Portal {
			st = append(st, eb("flush "+GuestChainAuth, "-F", GuestChainAuth))
			for _, m := range a.loadGuestAuth() {
				st = append(st, eb("authorised guest "+m, "-A", GuestChainAuth, "-s", m, "-j", "RETURN"))
			}
		}
		for _, x := range in {
			st = append(st, eb("guest rule", append([]string{"-A", GuestChainIn}, x...)...))
		}
		for _, x := range out {
			st = append(st, eb("guest rule", append([]string{"-A", GuestChainOut}, x...)...))
		}
		if !r.Portal && g.Chains[GuestChainAuth] {
			st = append(st, eb("flush "+GuestChainAuth, "-F", GuestChainAuth), eb("delete "+GuestChainAuth, "-X", GuestChainAuth))
		}
	}
	for _, j := range stale {
		st = append(st, cmdStep("remove stale guest jump", j.args("-D")...))
	}
	st = append(st, writeStep("write guest state", a.guestStatePath(), 0o600, []byte(state)))
	return st, foreign
}

// loadGuestAuth returns the authorised guest MACs (RunDir/guest-auth.txt).
func (a *Applier) loadGuestAuth() []string {
	b, err := a.readFile(a.guestAuthPath())
	if err != nil {
		return nil
	}
	macs, _ := normMACs(strings.Fields(string(b)))
	return macs
}

// AuthorizeGuest lets mac past the guest portal restriction: it is added to
// RunDir/guest-auth.txt (kept for this boot, folded into every rebuild) and,
// when the portal chain exists, as a RETURN rule in UDECO-GAUTH; then its
// flows are flushed. Expiry is the agent's job (call UnauthorizeGuest).
func (a *Applier) AuthorizeGuest(ctx context.Context, mac string) error {
	return a.setGuestAuth(ctx, mac, true)
}

// UnauthorizeGuest removes mac from the authorised guests (file and live
// chain), flushes its flows and kicks it, as a UniFi AP does on
// unauthorize-guest.
func (a *Applier) UnauthorizeGuest(ctx context.Context, mac string) error {
	return a.setGuestAuth(ctx, mac, false)
}

func (a *Applier) setGuestAuth(ctx context.Context, mac string, on bool) error {
	m := normMAC(mac)
	if m == "" {
		return fmt.Errorf("bcmwifi: guest authorisation: bad MAC %q", mac)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	list := a.loadGuestAuth()
	had := contains(list, m)
	switch {
	case on && !had:
		list = append(list, m)
	case !on && had:
		list = minus(list, []string{m})
	}
	sort.Strings(list)
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: authorised guests %v", list)
	} else if err := writeFileAtomic(a.fsPath(a.guestAuthPath()), []byte(strings.Join(list, "\n")), 0o600); err != nil {
		return err
	}
	if out, err := a.o.Run.Run(ctx, "ebtables", "-L", GuestChainAuth); err == nil {
		live := contains(parseEbMACs(string(out)), m)
		var st []Step
		if on && !live {
			st = append(st, cmdStep("authorise guest "+m, "ebtables", "-A", GuestChainAuth, "-s", m, "-j", "RETURN"))
		} else if !on && live {
			st = append(st, cmdStep("unauthorise guest "+m, "ebtables", "-D", GuestChainAuth, "-s", m, "-j", "RETURN"))
		}
		if len(st) > 0 {
			if a.o.DryRun {
				a.logPlan("dry-run guest authorisation", Plan{Steps: st})
			} else if err := a.execute(ctx, st); err != nil {
				return fmt.Errorf("bcmwifi: guest authorisation: %w", err)
			}
		}
	}
	if err := a.flushFlows(ctx, FlowScope{MAC: m}); err != nil {
		a.o.Logf("%v", err)
	}
	if !on {
		if err := a.Kick(ctx, m); err != nil && err != ErrNotOwned {
			a.o.Logf("bcmwifi: kick unauthorised guest %s: %v", m, err)
		}
	}
	return nil
}

// guestVerify checks that every guest vif is behind the guest chains.
func (a *Applier) guestVerify(ctx context.Context, l *layout) []string {
	vifs := l.guestVifs()
	if len(vifs) == 0 {
		return nil
	}
	g := a.readGuest(ctx)
	var probs []string
	if !g.Chains[GuestChainIn] || !g.Chains[GuestChainOut] {
		probs = append(probs, "guest ebtables chains missing")
	}
	for _, j := range wantJumps(vifs) {
		if !hasJump(g.Jumps, j) {
			probs = append(probs, fmt.Sprintf("guest vif %s has no %s %s jump to %s", j.Vif, j.Chain, j.Dir, j.Target))
		}
	}
	return probs
}
