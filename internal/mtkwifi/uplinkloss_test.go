// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// TestUplinkWatch: isolation after uplinkLossAfter without carrier, back
// after uplinkBackAfter with carrier; a flap shorter than either changes
// nothing; a new isolation waits uplinkIsoGap after the last restore.
func TestUplinkWatch(t *testing.T) {
	var w UplinkWatch
	t0 := time.Unix(1_800_000_000, 0)
	at := func(s int) time.Time { return t0.Add(time.Duration(s) * time.Second) }
	step := func(s int, carrier bool) bool { return w.Observe(carrier, at(s)) }
	if step(0, true) {
		t.Fatal("isolated with carrier")
	}
	for s := 1; s < 15; s++ {
		if step(s, false) {
			t.Fatalf("isolated after %d s", s-1)
		}
	}
	if !step(16, false) {
		t.Fatal("not isolated after 15 s without carrier")
	}
	step(17, true)
	if !step(46, true) {
		t.Fatal("restored after 29 s of carrier")
	}
	if step(47, true) {
		t.Fatal("not restored after 30 s of carrier")
	}
	// lost again at once: not before uplinkIsoGap from the restore (47 s)
	for s := 48; s < 47+int(uplinkIsoGap/time.Second); s += 5 {
		if step(s, false) {
			t.Fatalf("isolated again %d s after the restore", s-47)
		}
	}
	if !step(47+int(uplinkIsoGap/time.Second), false) {
		t.Error("not isolated once the gap was over")
	}
	// a carrier blip during isolation does not restore
	if !step(400, true) || !step(410, false) || !step(430, true) {
		t.Error("blip restored")
	}
}

// TestUplinkIsolation: with the uplink down every SSID but the
// management one goes down (one restart per radio); Verify and Tick see
// no drift and an Apply of the same controller plan changes nothing;
// carrier back brings every SSID back.
func TestUplinkIsolation(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	ctx := context.Background()
	d := home()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	if err := a.SetUplinkDown(ctx, true); err != nil {
		t.Fatal(err)
	}
	// "Example Network" (2.4 and 5 GHz) stays; ORCHID, the 2.4 GHz
	// SSID and the VLAN SSID go
	for _, ifc := range []string{"ra0", "rai0"} {
		if !f.up(ifc) {
			t.Errorf("%s down", ifc)
		}
	}
	for _, ifc := range []string{"ra1", "ra2", "rai1"} {
		if f.up(ifc) {
			t.Errorf("%s still up", ifc)
		}
	}
	if err := a.Verify(ctx, d); err != nil {
		t.Errorf("verify while isolated: %v", err)
	}
	*now += time.Minute
	if r, _ := a.Tick(ctx); r.NeedsApply || len(r.Foreign) > 0 {
		t.Errorf("tick while isolated: %+v", r)
	}
	n := len(f.log)
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := restarts(f.log[n:]); len(r) > 0 {
		t.Errorf("apply while isolated restarted: %v", r)
	}
	if err := a.SetUplinkDown(ctx, false); err != nil {
		t.Fatal(err)
	}
	for _, ifc := range []string{"ra0", "ra1", "ra2", "rai0", "rai1"} {
		if !f.up(ifc) {
			t.Errorf("%s down after the uplink came back", ifc)
		}
	}
	if err := a.Verify(ctx, d); err != nil {
		t.Errorf("verify after: %v", err)
	}
}

// TestUplinkIsolationKeep: the kept SSID is the configured one; with no
// such SSID served nothing is taken down (the unit must stay reachable).
func TestUplinkIsolationKeep(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	a.o.KeepSSID = "ORCHID"
	ctx := context.Background()
	p, _ := a.Plan(ctx, home())
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	a.SetUplinkDown(ctx, true)
	if !f.up("ra0") || f.up("ra1") || f.up("rai0") || f.up("rai1") {
		t.Errorf("keep ORCHID: ra0 %t ra1 %t rai0 %t rai1 %t", f.up("ra0"), f.up("ra1"), f.up("rai0"), f.up("rai1"))
	}
	if s := a.essid(ctx, "ra0"); s != "ORCHID" {
		t.Errorf("ra0 serves %q", s)
	}
	a.SetUplinkDown(ctx, false)

	a.o.KeepSSID = "nope"
	n := len(f.log)
	a.SetUplinkDown(ctx, true)
	if r := restarts(f.log[n:]); len(r) > 0 {
		t.Errorf("isolated without a management SSID: %v", r)
	}
	d := home()
	d.SSIDs = []bcmwifi.SSID{d.SSIDs[1]} // a VLAN SSID only
	if got := isolatedPlans(mustPlans(d), ""); got != nil {
		t.Errorf("isolated a VLAN-only plan: %+v", got)
	}
}

func mustPlans(d bcmwifi.Desired) map[string]RadioPlan { p, _ := plans(d, JCOW414, false); return p }
