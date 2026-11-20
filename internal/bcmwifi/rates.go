// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/translate"
)

// Minimum data rate and beacon rate per BSS (Options.MinRates).
//
// The X20's wl answers `wl -i <vif> rateset` per BSS (read on .205,
// 2026-11-18):
//
//	[ 1(b) 2(b) 5.5(b) 6 9 11(b) 12 18 24 36 48 54 ]   wl02 (2.4 GHz)
//	[ 6(b) 9 12(b) 18 24(b) 36 48 54 ]                 wl12 (5 GHz)
//	MCS SET : [ 0 1 ... ]   (then VHT and HE lines)
//
// and `wl rateset <list>` sets the legacy rates, each optionally suffixed "b"
// for a basic rate. Beacons and broadcast management frames go at the lowest
// basic rate, so a minimum rate also raises the beacon rate.
//
// Not verified on the hardware: whether setting it per BSS works, whether the
// BSS must be down (the agent only sets it while the BSS is down, during a
// full reconcile of the radio), and whether a legacy-only list leaves the
// MCS/VHT/HE sets alone. That is why it is behind Options.MinRates.
// TP-Link itself only sets the radio's rateset (nvram wlN_rateset=default,
// applied by wlconf); nothing on the unit sets a per-BSS one.
//
// Not hostapd: its supported_rates/basic_rates/beacon_rate exist in the
// X20's hostapd 2.9 (driver=nl80211), but the supported-rates elements of a
// Broadcom BSS come from the driver's rateset, and beacon_rate needs the
// driver to advertise legacy beacon-rate support (no iw on the unit to
// check). Without it the binary's nl80211 code fails the beacon setup
// ("nl80211: Driver does not support setting Beacon frame rate (legacy)",
// in /sbin/hostapd's strings), which would take the SSID down.
//
// wl's other rate knobs are not a minimum: 2g_rate/5g_rate and
// bg_rate/a_rate force one fixed rate, mrate/bg_mrate/a_mrate one multicast
// rate, per radio.

// legacyRate is one legacy rate in 500 kb/s units (1 Mb/s = 2, 5.5 = 11).
type legacyRate struct {
	half  int
	basic bool // basic in TP-Link's default set
}

// bandRates are the driver's default legacy ratesets as read on .205 (wl02
// and wl12; the BSS values, not the primaries').
var bandRates = map[string][]legacyRate{
	"ng": {{2, true}, {4, true}, {11, true}, {12, false}, {18, false}, {22, true}, {24, false}, {36, false}, {48, false}, {72, false}, {96, false}, {108, false}},
	"na": {{12, true}, {18, false}, {24, true}, {36, false}, {48, true}, {72, false}, {96, false}, {108, false}},
}

// cck reports an 802.11b rate (1, 2, 5.5, 11 Mb/s).
func cck(half int) bool { return half == 2 || half == 4 || half == 11 || half == 22 }

func rateToken(half int, basic bool) string {
	t := strconv.Itoa(half / 2)
	if half%2 == 1 {
		t += ".5"
	}
	if basic {
		t += "b"
	}
	return t
}

// RateOpts are the rest of a band's minimum-rate setting (the controller's
// beacon_rate and minrate_cck_rates.status): translate's type. BeaconKbps
// is the beacon/management rate (0 = the minimum); NoCCK drops the 802.11b
// rates (1, 2, 5.5, 11 Mb/s) on 2.4 GHz.
type RateOpts = translate.MinRateOpts

// ssidRateset is the wl rateset for s on band (Options.MinRates): its
// minimum-rate set, or the band's TP-Link default when s has no minimum
// there. Every vif gets an explicit rateset, so none inherits another BSS's
// minimum if the driver's rateset turns out to be per radio (not verified
// on the X20). nil only for an unknown band or a minimum no legacy rate
// meets (note says why).
func ssidRateset(s SSID, band string) (args []string, note string) {
	kbps, o := 0, RateOpts{}
	for k, v := range s.MinRateKbps {
		if rf.Norm(k) == band && v > 0 {
			kbps = v
		}
	}
	for k, v := range s.MinRateOpts {
		if rf.Norm(k) == band {
			o = v
		}
	}
	if kbps == 0 {
		return defaultRateset(band), ""
	}
	return minRateset(band, kbps, o)
}

// defaultRateset is TP-Link's legacy rateset on band, as minRateset's args.
func defaultRateset(band string) []string {
	var args []string
	for _, r := range bandRates[band] {
		args = append(args, rateToken(r.half, r.basic))
	}
	return args
}

// minRateset returns the wl rateset arguments for a minimum rate of kbps on
// band, the way the controller means it (translate/minrate.go):
//
//   - rates below the minimum are removed; on 2.4 GHz the 802.11b rates at
//     or above it stay unless o.NoCCK (a 6 Mb/s minimum keeps 11 Mb/s CCK);
//   - the beacon rate (o.BeaconKbps, else the minimum) becomes the lowest
//     basic rate, which is what the driver beacons at; rates between the
//     minimum and it are supported but not basic, and TP-Link's basic rates
//     above it stay basic.
//
// A beacon rate below the minimum (the controller's 24 Mb/s beacons for a
// 36-54 Mb/s minimum on 2.4 GHz) cannot be had with one rateset without
// letting clients use that rate too: the minimum wins and beacons go at it
// (noted). A minimum or beacon rate that is not in the set is raised to the
// next rate that is (noted). nil means not applied (note says why).
func minRateset(band string, kbps int, o RateOpts) (args []string, note string) {
	rates := bandRates[band]
	if rates == nil || kbps <= 0 {
		return nil, ""
	}
	noCCK := band == "ng" && o.NoCCK
	var set []legacyRate
	want := (kbps*2 + 999) / 1000 // round up to 500 kb/s units
	for _, r := range rates {
		if r.half >= want && !(noCCK && cck(r.half)) {
			set = append(set, r)
		}
	}
	if len(set) == 0 {
		return nil, fmt.Sprintf("minimum rate %d kbps is above the highest legacy rate on %s, not applied", kbps, band)
	}
	lo := set[0].half
	var notes []string
	if lo*500 != kbps {
		notes = append(notes, fmt.Sprintf("minimum rate %d kbps is not a legacy rate on %s, using %s Mb/s", kbps, band, rateToken(lo, false)))
	}
	bcn := lo
	if o.BeaconKbps > 0 {
		bw := (o.BeaconKbps*2 + 999) / 1000
		bcn = 0
		for _, r := range set {
			if r.half >= bw {
				bcn = r.half
				break
			}
		}
		switch {
		case bw < lo:
			bcn = lo
			notes = append(notes, fmt.Sprintf("beacon rate %d kbps is below the minimum on %s: beacons at %s Mb/s (one rateset for both here)", o.BeaconKbps, band, rateToken(lo, false)))
		case bcn == 0:
			bcn = lo
			notes = append(notes, fmt.Sprintf("beacon rate %d kbps is above the rateset on %s: beacons at %s Mb/s", o.BeaconKbps, band, rateToken(lo, false)))
		case bcn != bw:
			notes = append(notes, fmt.Sprintf("beacon rate %d kbps is not in the rateset on %s, using %s Mb/s", o.BeaconKbps, band, rateToken(bcn, false)))
		}
	}
	for _, r := range set {
		args = append(args, rateToken(r.half, r.half == bcn || r.half > bcn && r.basic))
	}
	return args, strings.Join(notes, "; ")
}

// parseRateset reads the legacy line of `wl rateset` ("[ 1(b) 2(b) 5.5 ]")
// into the canonical form minRateset produces ("1b 2b 5.5"). "" if the
// output has no legacy line.
func parseRateset(out string) string {
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "[") {
			continue
		}
		var toks []string
		for _, f := range strings.Fields(strings.Trim(line, "[]")) {
			toks = append(toks, strings.Replace(f, "(b)", "b", 1))
		}
		return strings.Join(toks, " ")
	}
	return ""
}
