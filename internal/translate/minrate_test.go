// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"strings"
	"testing"
)

// The minimum-rate keys exactly as Network 11.1.50 writes them for each
// 2.4 GHz rate group and for 5 GHz (ubntconf minrate factory), read into the
// intent's minimum, beacon rate and CCK choice.
func TestIntentMinRateFromController(t *testing.T) {
	ng := func(lines ...string) string {
		return strings.Replace(wlan(lines...), "parent=wifi1", "parent=wifi0", 1)
	}
	keys := func(min, bcn, cck string) []string {
		l := []string{"wireless.1.minrate_data=" + min, "wireless.1.beacon_rate=" + bcn, "wireless.1.mgmt_rate=" + bcn}
		if cck != "" {
			l = append(l, "wireless.1.minrate_cck_rates.status="+cck)
		}
		return l
	}
	for _, c := range []struct {
		name, cfg string
		band      string
		kbps      int // 0 = defaults
		opts      MinRateOpts
	}{
		{"2.4 control off (controller default)", ng(keys("1000", "1000", "true")...), "ng", 0, MinRateOpts{}},
		{"2.4 5.5 Mb/s", ng(keys("5500", "5500", "true")...), "ng", 5500, MinRateOpts{BeaconKbps: 5500}},
		{"2.4 6 Mb/s beacons at 11 CCK", ng(keys("6000", "11000", "true")...), "ng", 6000, MinRateOpts{BeaconKbps: 11000}},
		{"2.4 12 Mb/s no CCK", ng(keys("12000", "12000", "false")...), "ng", 12000, MinRateOpts{BeaconKbps: 12000, NoCCK: true}},
		{"2.4 36 Mb/s beacons at 24", ng(keys("36000", "24000", "false")...), "ng", 36000, MinRateOpts{BeaconKbps: 24000, NoCCK: true}},
		{"5 lowest is the default", wlan(keys("6000", "6000", "")...), "na", 0, MinRateOpts{}},
		{"5 24 Mb/s", wlan(keys("24000", "24000", "")...), "na", 24000, MinRateOpts{BeaconKbps: 24000}},
		{"mgmt_rate only", wlan("wireless.1.minrate_data=12000", "wireless.1.mgmt_rate=18000"), "na", 12000, MinRateOpts{BeaconKbps: 18000}},
	} {
		t.Run(c.name, func(t *testing.T) {
			// minrate_below_disable (the WLAN's minrate_*_advertising_rates)
			// is known: no "not carried" note for it
			in, notes := IntentFromCfg(c.cfg + "wireless.1.minrate_below_disable=true\n")
			if len(in.WLANs) != 1 {
				t.Fatalf("%d WLANs, notes %q", len(in.WLANs), notes)
			}
			w := in.WLANs[0]
			if c.kbps == 0 {
				if w.MinRateKbps != nil || w.MinRateOpts != nil {
					t.Errorf("defaults: minrate %v opts %v", w.MinRateKbps, w.MinRateOpts)
				}
			} else if !reflect.DeepEqual(w.MinRateKbps, map[string]int{c.band: c.kbps}) ||
				!reflect.DeepEqual(w.MinRateOpts, map[string]MinRateOpts{c.band: c.opts}) {
				t.Errorf("minrate %v opts %+v, want %s=%d %+v", w.MinRateKbps, w.MinRateOpts, c.band, c.kbps, c.opts)
			}
			for _, n := range notes {
				if strings.Contains(n, "minrate") {
					t.Errorf("note %q", n)
				}
			}
		})
	}
}

// One WLAN on both bands: each band keeps its own minimum and options, and
// a different minimum per band is not reported as a conflicting setting.
func TestIntentMinRateMergedBands(t *testing.T) {
	cfg := wlan("wireless.1.minrate_data=24000", "wireless.1.beacon_rate=24000",
		"wireless.2.ssid=net", "wireless.2.id=w1", "wireless.2.parent=wifi0", "wireless.2.devname=ath0",
		"wireless.2.minrate_data=6000", "wireless.2.beacon_rate=11000", "wireless.2.mgmt_rate=11000", "wireless.2.minrate_cck_rates.status=true")
	in, notes := IntentFromCfg(cfg)
	if len(in.WLANs) != 1 {
		t.Fatalf("%d WLANs", len(in.WLANs))
	}
	w := in.WLANs[0]
	if !reflect.DeepEqual(w.MinRateKbps, map[string]int{"na": 24000, "ng": 6000}) ||
		!reflect.DeepEqual(w.MinRateOpts, map[string]MinRateOpts{"na": {BeaconKbps: 24000}, "ng": {BeaconKbps: 11000}}) {
		t.Errorf("minrate %v opts %+v", w.MinRateKbps, w.MinRateOpts)
	}
	for _, n := range notes {
		if strings.Contains(n, "differ") {
			t.Errorf("note %q", n)
		}
	}
}
