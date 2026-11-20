// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"slices"
	"testing"
)

// Every served vif drops frames to the bridge group address (STP BPDUs)
// both ways, in a chain of its own with policy RETURN (so the guest chains
// still see everything else); the chain follows the served vifs, is
// rebuilt when something removes it, and goes with the hand-back.
func TestBGAFilter(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	c := f.eb.chains[chainBGA]
	if c == nil || c.policy != "RETURN" {
		t.Fatalf("chain %+v", c)
	}
	served := []string{"wl02", "wl03", "wl12"}
	var want []string
	for _, v := range served {
		want = append(want, "-i "+v+" -d BGA -j DROP", "-o "+v+" -d BGA -j DROP")
	}
	if !slices.Equal(c.rules, want) {
		t.Errorf("rules %q, want %q", c.rules, want)
	}
	if fw := f.eb.chains["FORWARD"].rules; len(fw) == 0 || !slices.Contains(fw, "-j "+chainBGA) {
		t.Errorf("FORWARD %q", fw)
	}
	if p2, _ := a.Plan(ctx, d); !p2.Empty() {
		t.Fatalf("plan after apply:\n%s", p2)
	}
	// something flushes it: Tick rebuilds it
	f.eb.chains[chainBGA].rules = nil
	f.eb.chains["FORWARD"].rules = slices.DeleteFunc(f.eb.chains["FORWARD"].rules, func(r string) bool { return r == "-j "+chainBGA })
	r, err := a.Tick(ctx)
	if err != nil || r.NeedsApply {
		t.Fatalf("tick %+v %v", r, err)
	}
	if len(f.eb.chains[chainBGA].rules) != len(want) || len(r.Foreign) == 0 {
		t.Errorf("not rebuilt: %q foreign %q", f.eb.chains[chainBGA].rules, r.Foreign)
	}
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	if f.eb.chains[chainBGA] != nil || slices.Contains(f.eb.chains["FORWARD"].rules, "-j "+chainBGA) {
		t.Errorf("filter left after hand-back: %+v %q", f.eb.chains[chainBGA], f.eb.chains["FORWARD"].rules)
	}
}

// The controller's bga_filter=disabled leaves that SSID's vifs out.
func TestBGAFilterOff(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	d.SSIDs[1].NoBGAFilter = true // a-main: wl02, wl12
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if r := f.eb.chains[chainBGA].rules; !slices.Equal(r, []string{"-i wl03 -d BGA -j DROP", "-o wl03 -d BGA -j DROP"}) {
		t.Errorf("rules %q", r)
	}
}
