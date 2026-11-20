// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"testing"
)

// A U6 Pro writes rrm 1 on every VAP whatever 11k says, and wnm 0 when the
// controller's BSS transition is off; the neighbor list upkeep alone
// follows 11k.
func TestDriverForRRMWNM(t *testing.T) {
	for _, c := range []struct {
		rrm, btm bool
		nbr      int
		wnm      string
	}{
		{true, true, 1, ""},
		{false, true, 0, ""},
		{true, false, 1, "0"},
		{false, false, 0, "0"},
	} {
		d := driverFor(vifAssign{Vif: "wl12", Band: "na", SSID: SSID{ID: "x", RRM: c.rrm, BSSTransition: c.btm}}, "02:00:00:00:00:01", 128, nil, false)
		if d.RRM != "0x33" || d.NbrScan != c.nbr || d.WNM != c.wnm {
			t.Errorf("11k %t 11v %t: rrm %q nbr %d wnm %q", c.rrm, c.btm, d.RRM, d.NbrScan, d.WNM)
		}
	}
}

// Every served vif gets the driver's DHCP unicast conversion (U6 idhcp 1);
// wnm 0 goes in with rrm while the radio is down.
func TestTakeoverDHCPUnicastWNM(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	f.state["wl12 dhcp_unicast"] = "0" // TP-Link's, as read 2026-11-20
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.SSIDs[1].BSSTransition = false // the main SSID; b-iot has none either
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	down, wnm, up := stepIndex(t, p, "radio wl1 down for dwds/rrm"), stepIndex(t, p, "wl -i wl12 wnm 0"), stepIndex(t, p, "radio wl1 up: ")
	if !(down < wnm && wnm < up) {
		t.Errorf("wnm step %d outside the radio down %d / up %d", wnm, down, up)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{"wl02", "wl03", "wl12"} {
		if !f.netdevExists(v) {
			continue
		}
		if got := f.state[v+" dhcp_unicast"]; got != "1" {
			t.Errorf("%s dhcp_unicast %q, want 1", v, got)
		}
	}
	if f.state["wl12 wnm"] != "0" {
		t.Errorf("wl12 wnm %q", f.state["wl12 wnm"])
	}
	// drift: re-asserted live by Tick, no radio restart
	f.state["wl12 dhcp_unicast"] = "0"
	f.reset()
	if r, err := a.Tick(ctx); err != nil || r.NeedsApply {
		t.Fatalf("tick %+v %v", r, err)
	}
	if f.state["wl12 dhcp_unicast"] != "1" || f.called("wl -i wl1 down") {
		t.Errorf("dhcp_unicast %q, radio down %t", f.state["wl12 dhcp_unicast"], f.called("wl -i wl1 down"))
	}
	// the hand-back puts TP-Link's 0 back on the recreated vif
	f.reset()
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.called("wl -i wl12 dhcp_unicast 0") && f.state["wl12 dhcp_unicast"] != "0" {
		t.Errorf("dhcp_unicast %q after hand-back", f.state["wl12 dhcp_unicast"])
	}
}
