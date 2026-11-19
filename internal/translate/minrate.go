// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import "strconv"

// Minimum data rate control (UniFi "2G/5G Data Rate Control").
//
// What the controller sends (Network 11.1.50, ubntconf minrate factory and
// the 2.4 GHz rate groups of com.ubnt.ace.api; read from the decompiled
// controller, 2026-11-19), per wireless.N:
//
//	minrate_data             the minimum rate, kbps (2.4 GHz: always sent,
//	                         1000 when the control is off; 5 GHz: only when
//	                         minrate_na_enabled)
//	beacon_rate, mgmt_rate   the beacon/management rate (equal). 5 GHz: the
//	                         minimum. 2.4 GHz by rate group:
//	                           1, 2, 5.5, 11 Mb/s -> the minimum, CCK on
//	                           6, 9              -> 11 Mb/s,     CCK on
//	                           12, 24            -> the minimum, CCK off
//	                           18, 36, 48, 54    -> 24 Mb/s,     CCK off
//	minrate_cck_rates.status 2.4 GHz only: keep the 802.11b (CCK) rates
//	minrate_below_disable    "true" when the WLAN's minrate_*_advertising_rates
//	                         is set: also stop advertising the lower rates
//
// None of this is gated by wifi_caps MINRATE_CTRL (0x200): the controller's
// supportMinRateCtrl() has no caller, the keys go to every AP.
//
// The Deco applies it as the BSS's legacy rateset (bcmwifi, wl rateset):
// rates below the minimum are removed from the set, so they are neither
// advertised nor used whatever minrate_below_disable says (a UAP's driver can
// keep advertising them; Broadcom's rateset is one list for both).

// MinRateOpts are the rest of a band's minimum-rate setting, carried next
// to WLANIntent.MinRateKbps.
type MinRateOpts struct {
	// BeaconKbps is the controller's beacon/management rate (beacon_rate,
	// else mgmt_rate); 0 = not sent (the backend beacons at the minimum).
	BeaconKbps int
	// NoCCK: 2.4 GHz without the 802.11b rates (minrate_cck_rates.status
	// false), so a 6 or 9 Mb/s minimum also drops 11 Mb/s CCK.
	NoCCK bool
}

// wlanMinRate reads wireless.N's minimum rate on band ("ng"/"na"). ok is
// false when the WLAN uses the band's default rates (no minimum, or the
// lowest rate the band has).
func wlanMinRate(cfg Cfg, w, band string) (kbps int, o MinRateOpts, ok bool) {
	sup, _ := wlanRates(cfg, w, legacyBand[band])
	if sup == nil {
		return 0, MinRateOpts{}, false
	}
	kbps, _ = strconv.Atoi(sup[0])
	for _, k := range []string{"beacon_rate", "mgmt_rate"} {
		if v, err := strconv.Atoi(cfg[w+k]); err == nil && v > 0 {
			o.BeaconKbps = v
			break
		}
	}
	o.NoCCK = band == "ng" && cfg[w+"minrate_cck_rates.status"] == "false"
	return kbps, o, true
}
