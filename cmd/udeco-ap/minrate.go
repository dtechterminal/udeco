// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
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
