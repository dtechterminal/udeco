// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

// rsWrite matches a `wl -i <vif> rateset <rates...>` write.
func rsWrite(argv []string) bool {
	return len(argv) > 4 && argv[0] == "wl" && argv[3] == "rateset"
}

// The rateset is written between `wl down` and `wl up` (radioDownSteps), and
// that write is not optional. These tests check that a refused write never
// leaves a radio down: whether the X20 accepts `wl rateset` with the radio
// down is not yet seen on a unit (min_rates is off on every Deco).

// Takeover with min rates, and the driver refuses every rateset write even
// with the radio down: the apply fails, Wi-Fi goes back to TP-Link, and
// both radios and TP-Link's BSSs are up.
func TestMinRatesRefusedAtTakeover(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.MinRates = true
	f.failOn = rsWrite
	p, err := a.Plan(context.Background(), minRateDesired())
	if err != nil {
		t.Fatal(err)
	}
	err = a.Apply(context.Background(), p)
	t.Logf("apply: %v", err)
	if err == nil {
		t.Fatal("apply succeeded with every rateset refused")
	}
	for _, r := range []string{"wl0", "wl1"} {
		if f.state[r+" radio"] == "down" {
			t.Errorf("%s left down", r)
		}
	}
	for _, v := range []string{"wl02", "wl12"} {
		if out, _ := f.Run(context.Background(), "wl", "-i", v, "bss"); strings.TrimSpace(string(out)) != "up" {
			t.Errorf("%s bss %q after hand-back", v, out)
		}
	}
}

// After a good apply, a new minimum whose rateset write fails once: the
// rollback to last-good brings the radio up with the old rateset, and the
// next Tick finds nothing to repair.
func TestMinRatesRefusedOnChange(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.MinRates = true
	d := minRateDesired()
	applyOK(t, a, d)
	d.SSIDs[1].MinRateKbps["na"] = 24000
	d.SSIDs[1].MinRateOpts["na"] = RateOpts{BeaconKbps: 24000}
	n := 0
	f.failOn = func(argv []string) bool {
		if rsWrite(argv) && argv[2] == "wl12" {
			n++
			return n == 1 // only the first: last-good's own write works
		}
		return false
	}
	p, _ := a.Plan(context.Background(), d)
	err := a.Apply(context.Background(), p)
	t.Logf("apply: %v", err)
	if err == nil {
		t.Fatal("no failure")
	}
	if f.state["wl1 radio"] == "down" {
		t.Error("wl1 left down")
	}
	if f.state["wl12 rateset"] != "12(b) 18 24(b) 36 48 54" {
		t.Errorf("last-good rateset not back: %q", f.state["wl12 rateset"])
	}
	// and a Tick right after finds nothing to do
	if r, err := a.Tick(context.Background()); err != nil || r.Steps != 0 || r.NeedsApply {
		t.Errorf("tick after rollback: %+v %v", r, err)
	}
}

// Steady state with min rates; dwds drifts on wl12, and the rateset write in
// the repair's radio down/up (the same radioDownSteps) fails: Tick runs
// every step (executeAll), so the radio still comes back up.
func TestMinRatesRefusedInTickRepair(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.MinRates = true
	applyOK(t, a, minRateDesired())
	f.state["wl1 radio"] = "down"
	f.Run(context.Background(), "wl", "-i", "wl12", "dwds", "1")
	f.state["wl1 radio"] = "up"
	f.failOn = rsWrite
	r, err := a.Tick(context.Background())
	t.Logf("tick: %+v %v", r, err)
	if f.state["wl1 radio"] == "down" {
		t.Error("wl1 left down by the tick repair")
	}
}
