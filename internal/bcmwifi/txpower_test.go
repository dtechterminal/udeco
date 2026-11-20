// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

// The presets apply live, the ceiling is learnt with no degrade on and kept
// (the target maximum may not move with txpwr_degrade), so a second plan
// is empty; TxPower reports the preset and the resulting power.
func TestTxPowerPresets(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	r := d.Radios["na"]
	r.TxPowerMode = "medium"
	d.Radios["na"] = r // wl1 target max 23.5 dBm (fixture)
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if got := f.state["wl1 txpwr_degrade"]; got != "37" {
		t.Errorf("wl1 txpwr_degrade %q, want 37", got)
	}
	if m, dbm, ok := a.TxPower("na"); !ok || m != "medium" || dbm != 14 {
		t.Errorf("TxPower na = %s %d %v", m, dbm, ok)
	}
	if m, dbm, ok := a.TxPower("ng"); !ok || m != "auto" || dbm != 24 {
		t.Errorf("TxPower ng = %s %d %v", m, dbm, ok)
	}
	for i := 0; i < 2; i++ {
		if p2, _ := a.Plan(ctx, d); !p2.Empty() {
			t.Fatalf("plan %d after apply:\n%s", i, p2)
		}
	}
	// a fresh agent (same RunDir) does not re-learn the ceiling from a
	// degraded reading
	b := newTestApplier(f, false)
	if p3, _ := b.Plan(ctx, d); !p3.Empty() {
		t.Fatalf("plan after an agent restart:\n%s", p3)
	}
	r.TxPowerMode = "low"
	d.Radios["na"] = r
	p4, _ := a.Plan(ctx, d)
	if !strings.Contains(p4.String(), "wl -i wl1 txpwr_degrade 74") || strings.Contains(p4.String(), "wl -i wl1 down") {
		t.Errorf("plan:\n%s", p4)
	}
}
