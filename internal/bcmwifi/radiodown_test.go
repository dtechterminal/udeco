// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

// dwds and rrm are accepted only while the radio is down (live on .205,
// 2026-11-19: "wl: Not down", exit 211, even for an unchanged value and with
// the BSS down). A takeover must still give every SSID its rrm (802.11k)
// and dwds, inside one radio down/up per radio, before the SSIDs are raised.
func TestTakeoverSetsRadioDownIovars(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	d := twoSSIDs()
	for i := range d.SSIDs {
		d.SSIDs[i].RRM = true
	}
	p, err := a.Plan(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Apply(ctx, p); err != nil {
		t.Fatalf("Apply = %v", err)
	}
	for _, v := range []string{"wl02", "wl03", "wl12"} {
		if got := f.state[v+" rrm"]; got != "0x33" {
			t.Errorf("%s rrm = %q, want 0x33", v, got)
		}
		if got := f.state[v+" dwds"]; got != "0" {
			t.Errorf("%s dwds = %q, want 0", v, got)
		}
	}
	for _, r := range []string{"wl0", "wl1"} {
		if got := f.state[r+" radio"]; got != "up" {
			t.Errorf("radio %s left %q", r, got)
		}
	}
	// Order per radio: start hostapd < radio down < rrm < radio up < raise.
	idx := func(sub string) int {
		for i, s := range p.Steps {
			if strings.Contains(s.String(), sub) {
				return i
			}
		}
		t.Fatalf("no step %q", sub)
		return -1
	}
	start, down, rrm, up, raise := idx("start hostapd on wl0"), idx("radio wl0 down for dwds/rrm"), idx("wl -i wl02 rrm 0x33"), idx("radio wl0 up"), idx("wl -i wl02 bss up")
	if !(start < down && down < rrm && rrm < up && up < raise) {
		t.Errorf("order start %d down %d rrm %d up %d raise %d", start, down, rrm, up, raise)
	}
}
