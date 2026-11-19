// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

const (
	gwMAC = "1c:6a:1b:c5:04:c2"
	gwIP  = "192.168.0.1"
	staA  = "02:11:22:33:44:01"
)

func guestDesired(portal bool) Desired {
	d := twoSSIDs()
	d.SSIDs = append(d.SSIDs, SSID{ID: "c-guest", SSID: "Guests", Bands: []string{"ng", "na"}, Enabled: true, Guest: true, Isolation: true, Security: SecOpen})
	d.Guest = &GuestPolicy{GatewayMAC: strings.ToUpper(gwMAC), GatewayIP: gwIP, DNS: []string{"192.168.0.1", "bad"},
		Restricted: []string{"192.168.0.0/16", "100.64.0.0/10"}, PreAllow: []string{"192.168.0.50"}, Portal: portal, PortalHost: "192.168.0.1"}
	return d
}

func ebRules(f *fakeDev, chain string) []string {
	c := f.eb.chains[chain]
	if c == nil {
		return nil
	}
	return c.rules
}

func TestGuestIsolation(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := guestDesired(false)
	p := applyOK(t, a, d)
	// c-guest is a br-lan SSID: wl03 (R23 places br-lan SSIDs first, so
	// b-iot's VLAN moves to wl04) and wl13.
	gv := a.layout(d).guestVifs()
	if strings.Join(gv, ",") != "wl03,wl13" {
		t.Fatalf("guest vifs %v", gv)
	}
	if f.bridgeOf("wl04") != "br-v20" || f.bridgeOf("wl03") != "br-lan" {
		t.Errorf("wl03 in %q, wl04 in %q", f.bridgeOf("wl03"), f.bridgeOf("wl04"))
	}
	// Chains exist with policy DROP and jumps sit first in FORWARD/INPUT.
	for _, c := range []string{chainGuestIn, chainGuestOut} {
		if f.eb.chains[c] == nil || f.eb.chains[c].policy != "DROP" {
			t.Fatalf("chain %s: %+v", c, f.eb.chains[c])
		}
	}
	if f.eb.chains[chainGuestAuth] != nil {
		t.Error("auth chain without a portal")
	}
	fw := ebRules(f, "FORWARD")
	if len(fw) != 4 || !contains(fw, "-i wl13 -j UDECO-GIN") || !contains(fw, "-o wl13 -j UDECO-GOUT") || !contains(fw, "-o wl03 -j UDECO-GOUT") {
		t.Errorf("FORWARD %v", fw)
	}
	if in := ebRules(f, "INPUT"); len(in) != 2 || !contains(in, "-i wl03 -j UDECO-GIN") {
		t.Errorf("INPUT %v", in)
	}
	in := strings.Join(ebRules(f, chainGuestIn), "\n")
	order := []string{
		"-p 0x888e -j ACCEPT",
		"-p ARP -j ACCEPT",
		"--ip-sport 68 --ip-dport 67 -j ACCEPT",
		"--ip-dst 192.168.0.1 --ip-proto udp --ip-dport 53 -j ACCEPT",
		"--ip-dst 192.168.0.50 -j ACCEPT",
		"-d ! " + gwMAC + " -j DROP",
		"-p IPv4 --ip-dst 192.168.0.1 -j ACCEPT",
		"-p IPv4 --ip-dst 10.0.0.0/8 -j DROP",
		"-p IPv4 --ip-dst 100.64.0.0/10 -j DROP",
		"--ip6-dst fc00::/7 -j DROP",
		"-j ACCEPT",
	}
	lines := ebRules(f, chainGuestIn)
	next := 0
	for _, w := range order {
		for next < len(lines) && !strings.Contains(lines[next], w) {
			next++
		}
		if next == len(lines) {
			t.Fatalf("UDECO-GIN lacks %q in order:\n%s", w, in)
		}
		next++
	}
	if lines[len(lines)-1] != "-j ACCEPT" {
		t.Errorf("last rule %q", lines[len(lines)-1])
	}
	if strings.Contains(in, "bad") {
		t.Error("invalid DNS entry used")
	}
	out := strings.Join(ebRules(f, chainGuestOut), "\n")
	for _, w := range []string{"-s " + gwMAC + " -j ACCEPT", "-p IPv4 --ip-src 192.168.0.50 -j ACCEPT"} {
		if !strings.Contains(out, w) {
			t.Errorf("UDECO-GOUT lacks %q:\n%s", w, out)
		}
	}
	// Fail closed: chains and jumps exist before the guest BSS comes up.
	if pol, up := stepIndex(t, p, "UDECO-GIN policy DROP"), stepIndex(t, p, "raise wl13"); pol > up {
		t.Error("guest BSS raised before its chains exist")
	}
	if j, fill := stepIndex(t, p, "ebtables -I FORWARD 1 -i wl13 -j UDECO-GIN"), stepIndex(t, p, "ebtables -A UDECO-GIN -p 0x888e"); j > fill {
		t.Error("jump added after the rules (chain should be filled while it drops)")
	}
	if p.Steps[len(p.Steps)-1].Argv[0] != "fc" {
		t.Errorf("plan does not end with a flow-cache flush: %s", p.Steps[len(p.Steps)-1])
	}
	if err := a.Verify(ctx, d); err != nil {
		t.Fatal(err)
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Fatalf("second plan not empty:\n%s", p)
	}

	// Removed behind our back: Verify fails, Tick rebuilds.
	f.eb.chains["FORWARD"].rules = nil
	delete(f.eb.chains, chainGuestOut)
	if err := a.Verify(ctx, d); err == nil {
		t.Error("Verify passed without guest chains")
	}
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("Tick %+v %v", r, err)
	}
	if !contains(ebRules(f, "FORWARD"), "-o wl13 -j UDECO-GOUT") || len(ebRules(f, chainGuestOut)) == 0 {
		t.Error("Tick did not rebuild the guest chains")
	}
	if !strings.Contains(strings.Join(r.Foreign, "\n"), "chain UDECO-GOUT missing") {
		t.Errorf("tick report %v", r.Foreign)
	}

	// No guest SSID any more: everything goes.
	d.SSIDs = d.SSIDs[:2]
	applyOK(t, a, d)
	for _, c := range ourChains {
		if f.eb.chains[c] != nil {
			t.Errorf("chain %s left", c)
		}
	}
	if len(ebRules(f, "FORWARD"))+len(ebRules(f, "INPUT")) != 0 {
		t.Error("jumps left")
	}
}

// A guest SSID is never served without a usable policy.
func TestGuestWithoutPolicyNotServed(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := guestDesired(false)
	d.Guest.GatewayMAC = ""
	p := applyOK(t, a, d)
	if f.state["wl13 bss"] == "up" {
		t.Error("guest SSID beacons without isolation")
	}
	n := strings.Join(p.Notes, "\n")
	if !strings.Contains(n, "gateway MAC") || !strings.Contains(n, "ssid c-guest: guest network without a usable guest policy") {
		t.Errorf("notes:\n%s", n)
	}
}

func TestGuestPortalAuthorize(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := guestDesired(true)
	applyOK(t, a, d)
	if c := f.eb.chains[chainGuestAuth]; c == nil || c.policy != "DROP" || len(c.rules) != 0 {
		t.Fatalf("auth chain %+v", c)
	}
	in := strings.Join(ebRules(f, chainGuestIn), "\n")
	for _, w := range []string{"--ip-dst 192.168.0.1 --ip-proto tcp --ip-dport 8880:8882 -j ACCEPT", "--ip-dport 8843 -j ACCEPT", "-j UDECO-GAUTH"} {
		if !strings.Contains(in, w) {
			t.Errorf("UDECO-GIN lacks %q", w)
		}
	}
	if strings.Index(in, "-j UDECO-GAUTH") > strings.Index(in, "-d ! ") {
		t.Error("authorisation checked after the gateway rule")
	}
	f.reset()
	if err := a.AuthorizeGuest(ctx, strings.ToUpper(staA)); err != nil {
		t.Fatal(err)
	}
	if r := ebRules(f, chainGuestAuth); len(r) != 1 || r[0] != "-s 02:11:22:33:44:01 -j RETURN" {
		t.Fatalf("auth rules %v", r)
	}
	if !f.called("fc flush --mac " + staA) {
		t.Error("no flow flush for the authorised guest")
	}
	// Idempotent, and kept across a rebuild of the chains.
	if err := a.AuthorizeGuest(ctx, staA); err != nil {
		t.Fatal(err)
	}
	if len(ebRules(f, chainGuestAuth)) != 1 {
		t.Error("duplicate auth rule")
	}
	delete(f.eb.chains, chainGuestIn)
	f.eb.chains["FORWARD"].rules = nil
	f.eb.chains["INPUT"].rules = nil
	if _, err := a.Tick(ctx); err != nil {
		t.Fatal(err)
	}
	if r := ebRules(f, chainGuestAuth); len(r) != 1 {
		t.Errorf("auth rules after rebuild %v", r)
	}
	f.reset()
	if err := a.UnauthorizeGuest(ctx, staA); err != nil {
		t.Fatal(err)
	}
	if r := ebRules(f, chainGuestAuth); len(r) != 0 {
		t.Errorf("auth rules after unauthorize %v", r)
	}
	if !f.called("deauthenticate " + staA) {
		t.Error("unauthorised guest not kicked")
	}
	if err := a.AuthorizeGuest(ctx, "nope"); err == nil {
		t.Error("bad MAC accepted")
	}
	// Portal off: the auth chain goes.
	applyOK(t, a, guestDesired(false))
	if f.eb.chains[chainGuestAuth] != nil {
		t.Error("auth chain left with the portal off")
	}
}

func TestNormalizeGuest(t *testing.T) {
	r, notes := normalizeGuest(&GuestPolicy{GatewayMAC: gwMAC, GatewayIP: gwIP, Restricted: []string{"fd00::/8", "10.1.2.3/8"}, Portal: true, PortalHost: "unifi.local"})
	if r == nil {
		t.Fatal(notes)
	}
	if strings.Join(r.DNS, ",") != gwIP {
		t.Errorf("DNS default %v", r.DNS)
	}
	if !contains(r.Restricted, "192.168.0.0/16") || !contains(r.Restricted, "10.0.0.0/8") || len(r.Restricted) != len(defaultRestricted) {
		t.Errorf("restricted %v", r.Restricted)
	}
	n := strings.Join(notes, "\n")
	if !strings.Contains(n, `"fd00::/8" is not an IPv4`) || !strings.Contains(n, "portal host") {
		t.Errorf("notes %s", n)
	}
	in, _ := r.render()
	for _, x := range in {
		if strings.Contains(strings.Join(x, " "), "8880") {
			t.Error("portal ports opened for an unresolved host")
		}
	}
	if r, _ := normalizeGuest(&GuestPolicy{GatewayMAC: gwMAC, GatewayIP: "fe80::1"}); r != nil {
		t.Error("IPv6 gateway accepted")
	}
	if r, _ := normalizeGuest(nil); r != nil {
		t.Error("nil policy accepted")
	}
}

func TestParseEbtablesListing(t *testing.T) {
	out := "Bridge table: filter\n\nBridge chain: FORWARD, entries: 3, policy: ACCEPT\n-i wl13 -j UDECO-GIN \n-o wl13 -j UDECO-GOUT , pcnt = 0 -- bcnt = 0\n-i eth1 -j blacklist\n"
	js := parseEbJumps("FORWARD", out)
	if len(js) != 2 || js[0] != (ebJump{"FORWARD", "-i", "wl13", chainGuestIn}) || js[1].Target != chainGuestOut {
		t.Errorf("%+v", js)
	}
	if m := parseEbMACs("-s 2:11:22:3:44:1 -j RETURN \n"); len(m) != 1 || m[0] != "02:11:22:03:44:01" {
		t.Errorf("%v", m)
	}
}
