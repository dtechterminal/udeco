// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func bssIDs(ids ...string) []BSS {
	var out []BSS
	for _, id := range ids {
		out = append(out, BSS{ID: id})
	}
	return out
}

// TestAssignSlots: a WLAN keeps its slot while others come and go; slot 0
// always has a WLAN, an unscheduled one when there is one; a WLAN that
// returns gets its old slot when it is still free.
func TestAssignSlots(t *testing.T) {
	slots, pins := assignSlots(bssIDs("a", "b", "c"), nil, 4)
	if !reflect.DeepEqual(slots, []int{0, 1, 2}) {
		t.Fatalf("fresh %v", slots)
	}
	// b goes (a schedule): c stays on slot 2
	slots, pins = assignSlots(bssIDs("a", "c"), pins, 4)
	if !reflect.DeepEqual(slots, []int{0, 2}) {
		t.Errorf("without b %v", slots)
	}
	// b comes back to slot 1; a new d takes slot 3
	slots, pins = assignSlots(bssIDs("a", "b", "c", "d"), pins, 4)
	if !reflect.DeepEqual(slots, []int{0, 1, 2, 3}) {
		t.Errorf("b back %v", slots)
	}
	// a (slot 0) goes: an unscheduled WLAN moves to slot 0
	list := bssIDs("b", "c", "d")
	list[0].Sched = true
	slots, _ = assignSlots(list, pins, 4)
	if !reflect.DeepEqual(slots, []int{1, 0, 3}) {
		t.Errorf("slot 0 refilled %v", slots)
	}
	// only scheduled WLANs: the first one takes slot 0 anyway
	list = bssIDs("b", "d")
	list[0].Sched, list[1].Sched = true, true
	slots, _ = assignSlots(list, pins, 4)
	if slots[0] != 0 && slots[1] != 0 {
		t.Errorf("no slot 0: %v", slots)
	}
	if s, _ := assignSlots(nil, pins, 4); len(s) != 0 {
		t.Errorf("empty %v", s)
	}
}

// TestPinnedApply: with BSS pinning a WLAN taken off (ORCHID, slot 1 of
// 2.4 GHz) leaves the WLAN after it on its netdev (ra2) and BSSID; the
// profile, the bridges, Verify and Tick follow the pinned slots; the pins
// survive an agent restart (run dir).
func TestPinnedApply(t *testing.T) {
	f := newFakeDev(t)
	a, now := clocked(f)
	a.o.PinSlots = true
	ctx := context.Background()
	d := home()
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	*now += time.Minute
	d.SSIDs[2].Enabled = false // ORCHID
	p, _ = a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !f.up("ra0") || f.up("ra1") || !f.up("ra2") {
		t.Errorf("ra0 %t ra1 %t ra2 %t", f.up("ra0"), f.up("ra1"), f.up("ra2"))
	}
	if s := a.essid(ctx, "ra2"); s != "Example Network(2.4GHz)" {
		t.Errorf("ra2 serves %q", s)
	}
	dat := readDat(t, f, 0)
	if v, _ := getKey(dat, "SSID3"); v != "Example Network(2.4GHz)" {
		t.Errorf("SSID3=%q", v)
	}
	if v, _ := getKey(dat, "MaxStaNum"); v != "32;10;32;1" {
		t.Errorf("MaxStaNum=%q (slot 1 keeps the vendor's, slot 2 served)", v)
	}
	*now += time.Minute
	if err := a.Verify(ctx, d); err != nil {
		t.Errorf("verify: %v", err)
	}
	if r, _ := a.Tick(ctx); r.NeedsApply || len(r.Foreign) > 0 {
		t.Errorf("tick %+v", r)
	}
	if _, err := os.Stat(filepath.Join(f.root, "tmp/udeco", slotsFile)); err != nil {
		t.Errorf("pins not saved: %v", err)
	}
	// a new agent (same boot): the pins hold, ORCHID comes back on ra1
	b, bnow := clocked(f)
	*bnow = *now + time.Minute
	b.o.PinSlots = true
	d.SSIDs[2].Enabled = true
	p, _ = b.Plan(ctx, d)
	if err := b.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if s := b.essid(ctx, "ra1"); s != "ORCHID" {
		t.Errorf("ra1 serves %q", s)
	}
	if s := b.essid(ctx, "ra2"); s != "Example Network(2.4GHz)" {
		t.Errorf("ra2 serves %q", s)
	}
}

// TestUnpinnedPositional: without the option the slots stay positional
// (and the plan JSON carries no slots).
func TestUnpinnedPositional(t *testing.T) {
	f := newFakeDev(t)
	a, _ := clocked(f)
	ctx := context.Background()
	d := home()
	d.SSIDs[2].Enabled = false
	p, _ := a.Plan(ctx, d)
	if err := a.Apply(ctx, p); err != nil {
		t.Fatal(err)
	}
	if !f.up("ra1") || f.up("ra2") || a.essid(ctx, "ra1") != "Example Network(2.4GHz)" {
		t.Errorf("positional: ra1 %t ra2 %t", f.up("ra1"), f.up("ra2"))
	}
	if a.live["ng"].Slots != nil {
		t.Errorf("slots without pinning: %v", a.live["ng"].Slots)
	}
}
