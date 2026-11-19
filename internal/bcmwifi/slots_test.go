// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// naDesired: SSIDs on 5 GHz only; vlan 0 = br-lan.
func naDesired(ssids ...SSID) Desired {
	return Desired{Country: "US", Radios: map[string]Radio{"ng": {Enabled: true}, "na": {Enabled: true}}, SSIDs: ssids}
}

func naSSID(id string, vlan int) SSID {
	return SSID{ID: id, SSID: "S-" + id, Bands: []string{"na"}, Enabled: true, Security: SecOpen, VLAN: vlan}
}

func off(s SSID) SSID { s.Enabled = false; return s }

func placed(l *layout) map[string]string {
	m := map[string]string{}
	for _, r := range l.Radios {
		for _, u := range r.Used {
			m[u.Vif] = u.SSID.ID
		}
	}
	return m
}

// The live .205 case: Home (br-lan) on wl12 and olive# (VLAN 3) on wl13.
// Adding, removing, disabling or scheduling off another SSID leaves both
// where they are; WLAN-id order alone (no prior) would have moved olive#.
func TestStableSlots(t *testing.T) {
	home, olive := naSSID("2", 0), naSSID("3", 3)
	live := map[string]string{"wl12": "2", "wl13": "3"}
	for _, c := range []struct {
		name  string
		d     Desired
		prior map[string]string
		want  map[string]string
	}{
		// a VLAN SSID with a lower WLAN id than olive#: id order would give
		// it wl13 and move olive# to wl14
		{"add", naDesired(naSSID("1", 7), home, olive), live,
			map[string]string{"wl12": "2", "wl13": "3", "wl14": "1"}},
		{"remove", naDesired(home, naSSID("4", 5)), map[string]string{"wl12": "2", "wl13": "3", "wl14": "4"},
			map[string]string{"wl12": "2", "wl14": "4"}},
		{"disable", naDesired(home, off(olive), naSSID("4", 5)), map[string]string{"wl12": "2", "wl13": "3", "wl14": "4"},
			map[string]string{"wl12": "2", "wl14": "4"}},
		// while olive# is off (its vif remembered in slots.json), a new
		// SSID takes a vif nobody waits for
		{"new while another is off", naDesired(home, off(olive), naSSID("1", 7)),
			mergeSlots(map[string]string{"wl12": "2", "wl13": "3"}, map[string]string{"wl12": "2"}),
			map[string]string{"wl12": "2", "wl14": "1"}},
		// back on: its old vif again
		{"back on", naDesired(home, olive, naSSID("1", 7)),
			mergeSlots(map[string]string{"wl12": "2", "wl13": "3"}, map[string]string{"wl12": "2", "wl14": "1"}),
			map[string]string{"wl12": "2", "wl13": "3", "wl14": "1"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			l := planLayout(c.d, fixtureVifs, layoutOpts{prior: c.prior})
			if got := placed(l); fmt.Sprint(got) != fmt.Sprint(c.want) {
				t.Errorf("placement %v, want %v\nnotes: %s", got, c.want, strings.Join(l.Notes, "; "))
			}
			for _, n := range l.Notes {
				if strings.Contains(n, "moved from") {
					t.Errorf("unexpected move: %s", n)
				}
			}
		})
	}
	// without a prior (first takeover): WLAN-id order, as before
	l := planLayout(naDesired(naSSID("1", 7), home, olive), fixtureVifs, layoutOpts{})
	if got := placed(l); got["wl13"] != "1" || got["wl14"] != "3" {
		t.Errorf("no prior: %v", got)
	}
}

// A move happens only when it cannot be avoided: with R23 a new br-lan SSID
// may only use wlN2/wlN3, so a VLAN SSID holding wl13 makes room (noted).
func TestStableSlotsUnavoidableMove(t *testing.T) {
	d := naDesired(naSSID("2", 0), naSSID("3", 3), naSSID("5", 0))
	l := planLayout(d, fixtureVifs, layoutOpts{prior: map[string]string{"wl12": "2", "wl13": "3"}})
	got := placed(l)
	if got["wl12"] != "2" || got["wl13"] != "5" || got["wl14"] != "3" {
		t.Errorf("placement %v", got)
	}
	if n := strings.Join(l.Notes, "\n"); !strings.Contains(n, "ssid 3: moved from wl13 to wl14") {
		t.Errorf("no move note:\n%s", n)
	}
	// with any vif allowed on br-lan the new SSID simply takes a free one
	l = planLayout(d, fixtureVifs, layoutOpts{anyVifOnLAN: true, prior: map[string]string{"wl12": "2", "wl13": "3"}})
	if got := placed(l); got["wl12"] != "2" || got["wl13"] != "3" || got["wl14"] != "5" {
		t.Errorf("anyVifOnLAN placement %v", got)
	}
}

// mergeSlots: the placement in force wins; the memory keeps only SSIDs that
// are not placed, on vifs nobody uses; never wlN1 or a primary.
func TestMergeSlots(t *testing.T) {
	got := mergeSlots(map[string]string{"wl13": "3", "wl14": "9", "wl02": "3", "wl11": "x", "wl1": "y"},
		map[string]string{"wl14": "4", "wl15": "3"})
	want := map[string]string{"wl02": "3", "wl14": "4", "wl15": "3"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("merged %v, want %v", got, want)
	}
}

// End to end on the fake unit: the applied placement is read back from the
// driver-state files and slots.json, so adding an SSID with a lower WLAN id
// keeps the others on their vifs; turning one off and on again returns it
// to its vif; and the per-vif files of a vif no longer used are removed
// (only those).
func TestApplierKeepsSlotsAndRemovesStaleFiles(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	apply := func(d Desired) {
		t.Helper()
		p, err := a.Plan(ctx, d)
		if err != nil {
			t.Fatal(err)
		}
		if err := a.Apply(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	home := naSSID("2", 0)
	olive := naSSID("3", 3)
	olive.Security, olive.Passphrase = SecWPA2, "olive-passphrase"
	olive.PSKs = []PSK{{Passphrase: "private-key-123", VLAN: 3}}
	apply(naDesired(home, olive))
	if got := placed(a.layout(naDesired(home, olive))); got["wl12"] != "2" || got["wl13"] != "3" {
		t.Fatalf("first placement %v", got)
	}
	for _, p := range []string{"/tmp/udeco/wl13.deny", "/tmp/udeco/wl13.psk", "/tmp/udeco/wl12.deny"} {
		if _, err := os.Stat(f.path(p)); err != nil {
			t.Fatalf("%s: %v", p, err)
		}
	}
	// a stray file of a vif nobody uses (left by an earlier build)
	f.write("/tmp/udeco/wl16.deny", "")

	// add a VLAN SSID with a lower WLAN id: olive# stays on wl13
	apply(naDesired(naSSID("1", 7), home, olive))
	got := placed(a.layout(naDesired(naSSID("1", 7), home, olive)))
	if got["wl12"] != "2" || got["wl13"] != "3" || got["wl14"] != "1" {
		t.Fatalf("after add %v", got)
	}
	if _, err := os.Stat(f.path("/tmp/udeco/wl16.deny")); !os.IsNotExist(err) {
		t.Errorf("stale wl16.deny left: %v", err)
	}

	// olive# off (a schedule window, or disabled): its vif's files go,
	// the others stay
	apply(naDesired(naSSID("1", 7), home, off(olive)))
	for _, p := range []string{"/tmp/udeco/wl13.deny", "/tmp/udeco/wl13.psk", "/tmp/udeco/wl13.accept"} {
		if _, err := os.Stat(f.path(p)); !os.IsNotExist(err) {
			t.Errorf("%s left after olive# went off: %v", p, err)
		}
	}
	for _, p := range []string{"/tmp/udeco/wl12.deny", "/tmp/udeco/wl14.deny"} {
		if _, err := os.Stat(f.path(p)); err != nil {
			t.Errorf("live vif file %s removed: %v", p, err)
		}
	}
	var mem map[string]string
	b, _ := os.ReadFile(f.path("/tmp/udeco/slots.json"))
	if json.Unmarshal(b, &mem) != nil || mem["wl13"] != "3" {
		t.Errorf("slots.json %s", b)
	}
	// back on: wl13 again, the others unmoved
	apply(naDesired(naSSID("1", 7), home, olive))
	got = placed(a.layout(naDesired(naSSID("1", 7), home, olive)))
	if got["wl12"] != "2" || got["wl13"] != "3" || got["wl14"] != "1" {
		t.Fatalf("after back on %v", got)
	}
	// and nothing more to do
	p, err := a.Plan(ctx, naDesired(naSSID("1", 7), home, olive))
	if err != nil || !p.Empty() {
		t.Fatalf("plan after apply: %v\n%s", err, p)
	}
}
