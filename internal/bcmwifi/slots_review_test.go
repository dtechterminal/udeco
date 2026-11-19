// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"math/rand"
	"strconv"
	"strings"
	"testing"
)

// Random add / remove / disable sequences on both radios, the prior carried
// from step to step the way the Applier does (placement in force overlaid
// on slots.json): no vif ever carries two SSIDs, a removed or disabled SSID
// is never placed, and an SSID served before and after a change keeps its
// vif unless a move is noted. With anyVifOnLAN (no R23) nothing ever moves.
func TestStableSlotsRandomSequences(t *testing.T) {
	for _, anyLAN := range []bool{false, true} {
		rng := rand.New(rand.NewSource(7))
		for run := 0; run < 200; run++ {
			ssids := map[string]SSID{}
			var mem map[string]string
			live := map[string]string{}
			for step := 0; step < 12; step++ {
				id := strconv.Itoa(1 + rng.Intn(9))
				switch s, ok := ssids[id]; {
				case !ok:
					bands := [][]string{{"ng"}, {"na"}, {"ng", "na"}}[rng.Intn(3)]
					ssids[id] = SSID{ID: id, SSID: "S-" + id, Bands: bands, Enabled: true, Security: SecOpen, VLAN: []int{0, 0, 5, 7}[rng.Intn(4)]}
				case rng.Intn(3) == 0:
					delete(ssids, id)
				default:
					s.Enabled = !s.Enabled
					ssids[id] = s
				}
				d := Desired{Country: "US", Radios: map[string]Radio{"ng": {Enabled: true}, "na": {Enabled: true}}}
				for i := 1; i <= 9; i++ {
					if s, ok := ssids[strconv.Itoa(i)]; ok {
						d.SSIDs = append(d.SSIDs, s)
					}
				}
				prior := mergeSlots(mem, live)
				l := planLayout(d, fixtureVifs, layoutOpts{prior: prior, anyVifOnLAN: anyLAN})
				now := map[string]string{}
				moved := strings.Contains(strings.Join(l.Notes, "\n"), "moved from")
				for _, r := range l.Radios {
					for _, u := range r.Used {
						if prev, dup := now[u.Vif]; dup {
							t.Fatalf("run %d step %d: %s carries %s and %s", run, step, u.Vif, prev, u.SSID.ID)
						}
						now[u.Vif] = u.SSID.ID
						if s, ok := ssids[u.SSID.ID]; !ok || !s.Enabled {
							t.Fatalf("run %d step %d: %s placed but removed/disabled", run, step, u.SSID.ID)
						}
					}
				}
				for v, id := range live {
					for nv, nid := range now {
						if nid == id && radioOf(nv) == radioOf(v) && nv != v && (anyLAN || !moved) {
							t.Fatalf("run %d step %d (anyLAN %v): %s moved %s -> %s without need\nnotes: %s", run, step, anyLAN, id, v, nv, strings.Join(l.Notes, "; "))
						}
					}
				}
				mem = mergeSlots(mem, now) // saveSlots
				live = now
			}
		}
	}
}
