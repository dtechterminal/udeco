// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"maps"
	"slices"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// Minimum data rate control (docs/deco/features/minrate.md).
//
// translate reads the controller's minrate_data/beacon_rate/
// minrate_cck_rates.status per WLAN and band; bcmwifi turns them into each
// BSS's wl rateset, but only with Options.MinRates, which the config's
// min_rates (takeover only) turns on: `wl rateset` per BSS has not been
// exercised on the X20 yet.

// minRateOpts maps a WLAN's per-band beacon rate and CCK choice.
func minRateOpts(m map[string]translate.MinRateOpts) map[string]bcmwifi.RateOpts {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]bcmwifi.RateOpts, len(m))
	for b, o := range m {
		out[b] = bcmwifi.RateOpts{BeaconKbps: o.BeaconKbps, NoCCK: o.NoCCK}
	}
	return out
}

// jioMinRates drops the SSIDs' minimum data rates for platform jio-mtk
// when min_rates is off. The controller sends minrate_data to every AP
// (translate/minrate.go), and mtkwifi applies whatever minimum reaches it as
// the radio's BasicRate, so the opt-in is enforced here.
func jioMinRates(d bcmwifi.Desired, on bool) (bcmwifi.Desired, []string) {
	if on {
		return d, nil
	}
	var notes []string
	ssids := make([]bcmwifi.SSID, len(d.SSIDs))
	for i, s := range d.SSIDs {
		bands := slices.Sorted(maps.Keys(s.MinRateKbps))
		for _, b := range bands {
			if k := s.MinRateKbps[b]; k > 0 {
				notes = append(notes, fmt.Sprintf("ssid %s: minimum rate %s=%d kbps not applied (min_rates is off)", s.ID, b, k))
			}
		}
		s.MinRateKbps, s.MinRateOpts = nil, nil
		ssids[i] = s
	}
	d.SSIDs = ssids
	return d, notes
}
