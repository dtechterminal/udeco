// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
)

func guestHome() bcmwifi.Desired {
	d := home()
	d.SSIDs = append(d.SSIDs, bcmwifi.SSID{ID: "g", SSID: "Garage Guest", Bands: []string{"5g"}, Enabled: true,
		Guest: true, Security: "wpa2", Passphrase: "secret-guest"})
	d.Guest = &bcmwifi.GuestPolicy{GatewayMAC: "00:11:22:33:44:55", GatewayIP: "192.168.0.1"}
	return d
}

// TestGuestPlans: a guest SSID is served only with a usable guest policy
// (fail closed, as bcmwifi).
func TestGuestPlans(t *testing.T) {
	ps, _ := plans(guestHome(), JCOW414, false)
	na := ps["na"]
	if len(na.BSS) != 3 || !na.BSS[2].Guest || na.BSS[2].SSID != "Garage Guest" {
		t.Errorf("na %+v", na.BSS)
	}
	d := guestHome()
	d.Guest = nil
	ps, notes := plans(d, JCOW414, false)
	if len(ps["na"].BSS) != 2 || !strings.Contains(joined(notes), `"Garage Guest": no usable guest policy`) {
		t.Errorf("without a policy: %+v %q", ps["na"].BSS, notes)
	}
}

// TestGuestApply: the guest chains are built (policy DROP before any
// rule) and the guest vif's jumps added before the guest SSID comes up;
// taking the guest SSID away removes them; the hand-back removes them.
func TestGuestApply(t *testing.T) {
	f := newFakeDev(t)
	a, _ := clocked(f)
	ctx := context.Background()
	p, _ := a.Plan(ctx, guestHome())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	idx := func(cmd string) int {
		for i, c := range f.log {
			if c == cmd {
				return i
			}
		}
		return -1
	}
	pol, jmp, up := idx("ebtables -P UDECO-GIN DROP"), idx("ebtables -I FORWARD 1 -i rai2 -j UDECO-GIN"), idx("ifconfig rai2 up")
	if pol < 0 || jmp < 0 || up < 0 || !(pol < jmp && jmp < up) {
		t.Errorf("policy %d, jump %d, guest up %d:\n%s", pol, jmp, up, strings.Join(f.log, "\n"))
	}
	for _, c := range []string{"ebtables -I FORWARD 1 -o rai2 -j UDECO-GOUT", "ebtables -I INPUT 1 -i rai2 -j UDECO-GIN",
		"ebtables -A UDECO-GIN -d ! 00:11:22:33:44:55 -j DROP"} {
		if idx(c) < 0 {
			t.Errorf("missing %q", c)
		}
	}
	if strings.Contains(strings.Join(f.log, "\n"), "-i rai0 -j UDECO") {
		t.Error("a LAN SSID got guest rules")
	}
	// again: nothing to do
	n := len(f.log)
	p, _ = a.Plan(ctx, guestHome())
	a.Apply(ctx, p)
	if c := cmdsFrom(f, n, "ebtables -A"); len(c) > 0 {
		t.Errorf("rebuilt unchanged chains: %v", c)
	}
	// the guest SSID goes
	n = len(f.log)
	p, _ = a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.log[n:], "\n")
	for _, c := range []string{"ebtables -D FORWARD -i rai2 -j UDECO-GIN", "ebtables -X UDECO-GIN", "ebtables -X UDECO-GOUT"} {
		if !strings.Contains(got, c) {
			t.Errorf("missing %q in\n%s", c, got)
		}
	}
	// hand-back with a guest SSID up
	p, _ = a.Plan(ctx, guestHome())
	a.Apply(ctx, p)
	n = len(f.log)
	a.mu.Lock()
	a.restoreBaseline(ctx)
	a.mu.Unlock()
	if !strings.Contains(strings.Join(f.log[n:], "\n"), "ebtables -X UDECO-GIN") {
		t.Errorf("hand-back left the guest chains")
	}
}

// TestGuestPortalAuth: with the portal on, an authorised guest gets its
// RETURN rule in the auth chain, kept across rebuilds; unauthorising
// removes it and disconnects the guest.
func TestGuestPortalAuth(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := guestHome()
	d.Guest.Portal, d.Guest.PortalHost = true, "192.168.0.2"
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute // past the restart's settle time (the disconnect is live iwpriv)
	n := len(f.log)
	if err := a.AuthorizeGuest(ctx, "AA:BB:CC:DD:EE:01"); err != nil {
		t.Fatal(err)
	}
	if c := cmdsFrom(f, n, "ebtables -A UDECO-GAUTH -s aa:bb:cc:dd:ee:01 -j RETURN"); len(c) != 1 {
		t.Errorf("authorise: %v", f.log[n:])
	}
	n = len(f.log)
	if err := a.UnauthorizeGuest(ctx, "aa:bb:cc:dd:ee:01"); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(f.log[n:], "\n")
	if !strings.Contains(got, "ebtables -D UDECO-GAUTH -s aa:bb:cc:dd:ee:01 -j RETURN") || !strings.Contains(got, "DisConnectSta=AA:BB:CC:DD:EE:01") {
		t.Errorf("unauthorise:\n%s", got)
	}
}
