// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

// The wl rateset for each minimum the controller can send (its 2.4 GHz rate
// groups: beacon_rate and minrate_cck_rates.status per group; 5 GHz beacons
// at the minimum), and the edge cases.
func TestMinRateset(t *testing.T) {
	for _, c := range []struct {
		band       string
		kbps, bcn  int
		noCCK      bool
		want, note string
	}{
		// 2.4 GHz group 1, 2, 5.5, 11 Mb/s: CCK on, beacons at the minimum
		{"ng", 1000, 1000, false, "1b 2b 5.5b 6 9 11b 12 18 24 36 48 54", ""}, // TP-Link's own wl02 set
		{"ng", 2000, 2000, false, "2b 5.5b 6 9 11b 12 18 24 36 48 54", ""},
		{"ng", 5500, 5500, false, "5.5b 6 9 11b 12 18 24 36 48 54", ""},
		{"ng", 11000, 11000, false, "11b 12 18 24 36 48 54", ""},
		// group 6, 9: CCK on, beacons at 11 Mb/s (11 stays, 6 and 9 not basic)
		{"ng", 6000, 11000, false, "6 9 11b 12 18 24 36 48 54", ""},
		{"ng", 9000, 11000, false, "9 11b 12 18 24 36 48 54", ""},
		// group 12, 24: CCK off, beacons at the minimum
		{"ng", 12000, 12000, true, "12b 18 24 36 48 54", ""},
		{"ng", 24000, 24000, true, "24b 36 48 54", ""},
		// group 18, 36, 48, 54: CCK off, beacons at 24 Mb/s
		{"ng", 18000, 24000, true, "18 24b 36 48 54", ""},
		{"ng", 36000, 24000, true, "36b 48 54", "beacon rate 24000 kbps is below the minimum"},
		{"ng", 54000, 24000, true, "54b", "beacon rate 24000 kbps is below the minimum"},
		// 5 GHz: beacons at the minimum, TP-Link's basic rates above it stay
		{"na", 6000, 6000, false, "6b 9 12b 18 24b 36 48 54", ""}, // TP-Link's own wl12 set
		{"na", 12000, 12000, false, "12b 18 24b 36 48 54", ""},
		{"na", 18000, 18000, false, "18b 24b 36 48 54", ""},
		{"na", 36000, 36000, false, "36b 48 54", ""},
		// no beacon rate sent: beacons at the minimum
		{"ng", 6000, 0, false, "6b 9 11b 12 18 24 36 48 54", ""},
		// CCK off with a 6 Mb/s minimum (minrate_cck_rates.status=false)
		{"ng", 6000, 6000, true, "6b 9 12 18 24 36 48 54", ""},
		// beacon rate removed with the CCK rates
		{"ng", 6000, 11000, true, "6 9 12b 18 24 36 48 54", "beacon rate 11000 kbps is not in the rateset on ng, using 12 Mb/s"},
		{"na", 12000, 60000, false, "12b 18 24b 36 48 54", "beacon rate 60000 kbps is above the rateset"},
		{"na", 7000, 0, false, "9b 12b 18 24b 36 48 54", "not a legacy rate"},
		{"na", 12000, 15000, false, "12 18b 24b 36 48 54", "beacon rate 15000 kbps is not in the rateset on na, using 18 Mb/s"},
		{"na", 60000, 0, false, "", "above the highest"},
		{"na", 0, 0, false, "", ""},
		{"6e", 12000, 0, false, "", ""},
	} {
		args, note := minRateset(c.band, c.kbps, RateOpts{BeaconKbps: c.bcn, NoCCK: c.noCCK})
		if got := strings.Join(args, " "); got != c.want || !strings.Contains(note, c.note) || c.note == "" && note != "" {
			t.Errorf("%s %d beacon %d nocck %v: %q note %q, want %q note %q", c.band, c.kbps, c.bcn, c.noCCK, got, note, c.want, c.note)
		}
	}
	// The getter output read on .205.
	out := "[ 6(b) 9 12(b) 18 24(b) 36 48 54 ]\nMCS SET : [ 0 1 2 3 ]\nVHT SET : 0x1 1x1\n"
	if got := parseRateset(out); got != "6b 9 12b 18 24b 36 48 54" {
		t.Errorf("parseRateset = %q", got)
	}
}

// ssidRateset: an SSID without a minimum on a band gets TP-Link's default
// set there (explicitly), band names are normalised, and the options go with
// their band.
func TestSSIDRateset(t *testing.T) {
	s := SSID{MinRateKbps: map[string]int{"2g": 6000}, MinRateOpts: map[string]RateOpts{"2g": {BeaconKbps: 11000}}}
	if got, _ := ssidRateset(s, "ng"); strings.Join(got, " ") != "6 9 11b 12 18 24 36 48 54" {
		t.Errorf("ng %q", got)
	}
	if got, _ := ssidRateset(s, "na"); strings.Join(got, " ") != "6b 9 12b 18 24b 36 48 54" {
		t.Errorf("na without a minimum %q, want TP-Link's default", got)
	}
	if got, _ := ssidRateset(SSID{}, "ng"); strings.Join(got, " ") != "1b 2b 5.5b 6 9 11b 12 18 24 36 48 54" {
		t.Errorf("ng without a minimum %q, want TP-Link's default", got)
	}
}

func minRateDesired() Desired {
	d := twoSSIDs()
	// as the controller sends a 6 Mb/s (2.4) and 12 Mb/s (5) minimum
	d.SSIDs[1].MinRateKbps = map[string]int{"ng": 6000, "na": 12000}
	d.SSIDs[1].MinRateOpts = map[string]RateOpts{"ng": {BeaconKbps: 11000}, "na": {BeaconKbps: 12000}}
	return d
}

// Feature flag off (default): no rateset is ever set, and the plan says so.
func TestMinRatesOffByDefault(t *testing.T) {
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	p := applyOK(t, a, minRateDesired())
	if f.called(" rateset ") {
		t.Error("rateset set with MinRates off")
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "minimum rate ng=6000 kbps not applied (Options.MinRates is off") {
		t.Errorf("notes %v", p.Notes)
	}
}

// Feature flag on: the rateset is set while the BSS is down, before hostapd
// starts; a changed minimum reconciles the radio; the hand-back restores
// TP-Link's rateset.
func TestMinRatesOn(t *testing.T) {
	ctx := context.Background()
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	a.o.MinRates = true
	d := minRateDesired()
	p := applyOK(t, a, d)
	rs := stepIndex(t, p, "wl -i wl12 rateset 12b 18 24b 36 48 54")
	if lo := stepIndex(t, p, "lower wl12"); lo > rs {
		t.Error("rateset set while the BSS was up")
	}
	if up := stepIndex(t, p, "raise wl12"); up < rs {
		t.Error("rateset set after the BSS came up")
	}
	stepIndex(t, p, "wl -i wl02 rateset 6 9 11b 12 18 24 36 48 54")
	// the 2.4 GHz SSID without a minimum gets TP-Link's set, explicitly
	stepIndex(t, p, "rateset 1b 2b 5.5b 6 9 11b 12 18 24 36 48 54")
	if strings.Contains(strings.Join(p.Notes, "\n"), "minimum rate") {
		t.Errorf("notes %v", p.Notes)
	}
	if p, _ := a.Plan(ctx, d); !p.Empty() {
		t.Fatalf("second plan:\n%s", p)
	}
	d.SSIDs[1].MinRateKbps["na"] = 24000
	d.SSIDs[1].MinRateOpts["na"] = RateOpts{BeaconKbps: 24000}
	p2, _ := a.Plan(ctx, d)
	if !p2.disruptive {
		t.Error("a new minimum rate did not reconcile the radio")
	}
	stepIndex(t, p2, "wl -i wl12 rateset 24b 36 48 54")
	if err := a.handback(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.called("wl -i wl12 rateset 6b 9 12b 18 24b 36 48 54") || !f.called("wl -i wl02 rateset 1b 2b 5.5b 6 9 11b 12 18 24 36 48 54") {
		t.Error("TP-Link's rateset not restored")
	}
	if f.state["wl05 rateset"] != "" && f.state["wl05 rateset"] != "1(b) 2(b) 5.5(b) 6 9 11(b) 12 18 24 36 48 54" {
		t.Errorf("wl05 rateset %q after hand-back, want TP-Link's", f.state["wl05 rateset"])
	}
}
