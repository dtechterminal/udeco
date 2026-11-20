// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"maps"
	"slices"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/translate"
)

// Minimum data rate control (docs/deco/features/minrate.md).
//
// translate reads the controller's minrate_data/beacon_rate/
// minrate_cck_rates.status per WLAN and band; bcmwifi turns them into each
// BSS's wl rateset, but only with Options.MinRates, which the config's
// min_rates (takeover only) turns on: `wl rateset` per BSS has not been
// exercised on the X20 yet.

// minRateOpts is a WLAN's per-band beacon rate and CCK choice for bcmwifi:
// a copy (bcmwifi.RateOpts is translate.MinRateOpts), nil when there is none.
func minRateOpts(m map[string]translate.MinRateOpts) map[string]bcmwifi.RateOpts {
	if len(m) == 0 {
		return nil
	}
	return maps.Clone(m)
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
