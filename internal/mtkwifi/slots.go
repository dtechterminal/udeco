// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// BSS slot pinning (Options.PinSlots, config bss_pinning; off by default).
//
// Without it a radio's SSIDs take the profile slots in the controller's
// order, so taking one SSID off (a schedule, a disabled WLAN) moves every
// later SSID to another netdev and BSSID (its clients' PMKSA caches and
// the controller's VAP BSSIDs change). A U6 has one VAP per WLAN. With
// pinning each WLAN keeps its slot (WLAN id -> slot, per radio, in the run
// dir, so for the boot): a WLAN that goes and comes back gets its slot
// again while it is free.
//
// Slot 0 (ra0, rai0) must be up whenever the radio is: its netdev coming
// up reads the profile, and the others' BSSIDs derive from it. It goes to
// a WLAN without a schedule when there is one; when its WLAN goes away,
// another one moves to slot 0 (that one's BSSID changes).
//
// A change of slots is still a radio restart (the profile is re-read).
// Taking a single BSS down and up instead (ifconfig rarN down/up with
// slot 0 up: the drivers' per-BSS counters keep the radio running) is the
// next step, untested on the unit: docs/deco/features/garage-parity.md
// gives the on-unit test.

const slotsFile = "mtk-slots.json" // RunDir: WLAN id -> slot per band

// assignSlots gives each BSS of list a slot (0..n-1, parallel to list)
// from pins (WLAN id -> slot), and returns the pins to keep: the ones of
// list, and the earlier ones whose slot is still free.
func assignSlots(list []BSS, pins map[string]int, n int) ([]int, map[string]int) {
	slots := make([]int, len(list))
	used := map[int]int{} // slot -> index in list
	for i := range slots {
		slots[i] = -1
	}
	for i, b := range list {
		if s, ok := pins[b.ID]; ok && s >= 0 && s < n {
			if _, taken := used[s]; !taken {
				slots[i], used[s] = s, i
			}
		}
	}
	if _, ok := used[0]; !ok && len(list) > 0 {
		pick := -1
		for _, pass := range []bool{true, false} {
			for i, b := range list {
				// first pass: an unscheduled WLAN not yet placed, then
				// one placed elsewhere; then any WLAN
				if pick < 0 && (!pass || !b.Sched) && slots[i] < 0 {
					pick = i
				}
			}
			for i, b := range list {
				if pick < 0 && (!pass || !b.Sched) {
					pick = i
				}
			}
		}
		if s := slots[pick]; s >= 0 {
			delete(used, s)
		}
		slots[pick], used[0] = 0, pick
	}
	for i := range list {
		if slots[i] >= 0 {
			continue
		}
		for s := 1; s < n; s++ {
			if _, taken := used[s]; !taken {
				slots[i], used[s] = s, i
				break
			}
		}
	}
	next := map[string]int{}
	for i, b := range list {
		if slots[i] >= 0 {
			next[b.ID] = slots[i]
		}
	}
	for id, s := range pins {
		if _, ok := next[id]; ok {
			continue
		}
		if _, taken := used[s]; !taken {
			next[id] = s
		}
	}
	return slots, next
}

// pinned is want with each radio's BSSes in their pinned slots (without
// PinSlots: want), and the pins to save once it is applied.
func (a *Applier) pinned(want map[string]RadioPlan) (map[string]RadioPlan, map[string]map[string]int) {
	if !a.o.PinSlots {
		return want, nil
	}
	if a.pins == nil {
		a.pins = map[string]map[string]int{}
		if b, err := os.ReadFile(a.dev(filepath.Join(a.o.RunDir, slotsFile))); err == nil {
			_ = json.Unmarshal(b, &a.pins)
		}
	}
	out, next := map[string]RadioPlan{}, map[string]map[string]int{}
	for _, rd := range a.o.Layout {
		rp, ok := want[rd.Band]
		if !ok {
			continue
		}
		slots, pins := assignSlots(rp.BSS, a.pins[rd.Band], len(rd.Ifaces))
		next[rd.Band] = pins
		if rp.On && len(rp.BSS) > 0 {
			rp.Slots = slots
		}
		out[rd.Band] = rp
	}
	return out, next
}

// savePins keeps next as the pins (an apply of the plan pinned with it
// succeeded).
func (a *Applier) savePins(next map[string]map[string]int) {
	if next == nil {
		return
	}
	a.pins = next
	j, _ := json.Marshal(next)
	if err := writeFile(a.dev(filepath.Join(a.o.RunDir, slotsFile)), j, 0o644); err != nil {
		a.o.Logf("mtkwifi: saving the BSS slots: %v", err)
	}
}
