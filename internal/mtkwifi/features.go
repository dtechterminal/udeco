// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"slices"
	"strconv"
	"strings"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// The controller's per-SSID and per-radio features beyond the BSS list.
//
// Every one is written to the driver profile (profile()), so a change
// restarts the radio: structural() keeps them. The drivers have them per
// BSS (RRMEnable, WNMEnable, AssocReqRssiThres, APSDCapable on the MT7663)
// or per radio only (DtimPeriod, BasicRate, IgmpSnEnable); a per-SSID
// setting the driver has per radio is folded (DTIM: the lowest; minimum
// rate: only when every SSID of the radio has one) with a note. What the
// controller asks for and this unit does not do is noted, never dropped
// silently; an SSID whose safety depends on a missing feature (RADIUS MAC
// authentication) is not served at all.

// ssidNotes notes, once per SSID, what the controller asks for that this
// platform does not apply, and returns the SSIDs never to serve. RADIUS
// MAC authentication fails closed (as bcmwifi does): neither driver nor
// rtdot1xd has it, and the SSID without it would admit every station.
func ssidNotes(ssids []bcmwifi.SSID, note func(string, ...any)) map[string]bool {
	refused := map[string]bool{}
	for _, s := range ssids {
		if !s.Enabled {
			continue
		}
		if s.Radius != nil && s.Radius.MACAuth {
			note("SSID %q: RADIUS MAC authentication is not supported by this driver: not served", s.SSID)
			refused[s.ID] = true
			continue
		}
		if len(s.PSKs) > 0 {
			note("SSID %q: private pre-shared keys (PPSK) are not supported: only the WLAN passphrase is served", s.SSID)
		}
		if r := s.RateLimit; r != nil && (r.DownKbps > 0 || r.UpKbps > 0) {
			note("SSID %q: per-client rate limit (down %d, up %d kbit/s) not applied (no traffic shaping on this unit)", s.SSID, r.DownKbps, r.UpKbps)
		}
		if s.ProxyARP {
			note("SSID %q: proxy ARP not applied", s.SSID)
		}
		if s.Hotspot2 != nil {
			note("SSID %q: Hotspot 2.0 is not advertised", s.SSID)
		}
	}
	return refused
}

// bssNotes notes what of s the BSS b on rd does not carry.
func bssNotes(s bcmwifi.SSID, b BSS, rd RadioDef, note func(string, ...any)) {
	if s.FT {
		if rd.Band == "ng" {
			note("%s: SSID %q: 802.11r is not supported by the %s driver: clients roam with a full association", rd.Band, s.SSID, rd.HWName)
		} else {
			note("%s: SSID %q: 802.11r is not applied (no IAPP daemon on this unit to share keys with other APs): clients roam with a full association", rd.Band, s.SSID)
		}
	}
	if s.UAPSD && !rd.UAPSD {
		note("%s: SSID %q: U-APSD is not supported by the %s driver", rd.Band, s.SSID, rd.HWName)
	}
	if want := pmfLevel(s.PMF); b.Auth != "OPEN" && want > b.PMF {
		note("%s: SSID %q: PMF %s not applied: served with PMF %s", rd.Band, s.SSID, s.PMF, pmfName(b.PMF))
	}
}

func pmfLevel(p string) int {
	switch p {
	case "required":
		return 2
	case "optional":
		return 1
	}
	return 0
}

func pmfName(l int) string { return []string{"disabled", "optional", "required"}[l] }

// radioFeatures sets rp's per-radio settings from the radio and the SSIDs
// it serves (served is parallel to rp.BSS).
func radioFeatures(rp *RadioPlan, rd RadioDef, ri bcmwifi.Radio, served []bcmwifi.SSID, note func(string, ...any)) {
	band := rd.Band
	// DTIM: one DtimPeriod per radio; the lowest asked keeps every SSID's
	// power-save clients woken at least as often as they asked
	var dtims []int
	for _, s := range served {
		if v := bandValue(s.DTIM, band); v > 0 {
			v = min(v, 255)
			if !slices.Contains(dtims, v) {
				dtims = append(dtims, v)
			}
			if rp.DTIM == 0 || v < rp.DTIM {
				rp.DTIM = v
			}
		}
	}
	if len(dtims) > 1 {
		slices.Sort(dtims)
		note("%s: DTIM is one value per radio in this driver: %d for every SSID (asked: %v)", band, rp.DTIM, dtims)
	}

	// minimum RSSI: AssocReqRssiThres refuses associations below it (the
	// driver takes -100..-1; 0 is off)
	switch {
	case ri.MinRSSI < 0 && ri.MinRSSI >= -100:
		rp.MinRSSI = ri.MinRSSI
		note("%s: minimum RSSI %d dBm refuses associations below it; associated stations are not disconnected", band, ri.MinRSSI)
	case ri.MinRSSI != 0:
		note("%s: minimum RSSI %d dBm is out of range (-100..-1): off", band, ri.MinRSSI)
	}

	for _, b := range rp.BSS {
		if b.RRM {
			note("%s: 802.11k is advertised, but no neighbour list is configured (the driver has no command to add entries)", band)
			break
		}
	}

	// IGMP snooping (the driver's multicast-to-unicast) is per radio and on
	// in the vendor's profiles: turned on when an SSID asks, never off
	var m2u, plain []string
	for _, s := range served {
		if s.MulticastToUnicast {
			m2u = append(m2u, s.SSID)
		} else {
			plain = append(plain, s.SSID)
		}
	}
	rp.IgmpSn = len(m2u) > 0
	switch {
	case len(m2u) > 0 && len(plain) > 0:
		note("%s: multicast enhancement (IGMP snooping) is per radio in this driver: on for every SSID (asked by %q)", band, m2u)
	case len(m2u) == 0:
		note("%s: multicast enhancement off: IGMP snooping stays as the vendor set it (never turned off)", band)
	}

	minRate(rp, band, served, note)
}

// minRate sets rp.BasicRate from the SSIDs' minimum data rates. The driver
// has one BasicRate per radio and no supported-rates or beacon-rate
// setting, so a minimum only changes which rates are basic. It is applied
// only when every SSID of the radio has one: an SSID without a minimum
// keeps the vendor's basic rates for the whole radio.
func minRate(rp *RadioPlan, band string, served []bcmwifi.SSID, note func(string, ...any)) {
	var without []string
	var asked []int
	minK, noCCK, beacon := 0, true, 0
	for _, s := range served {
		k := bandValue(s.MinRateKbps, band)
		if k <= 0 {
			without = append(without, s.SSID)
			continue
		}
		if !slices.Contains(asked, k) {
			asked = append(asked, k)
		}
		o := bandRateOpts(s.MinRateOpts, band)
		noCCK = noCCK && o.NoCCK
		if o.BeaconKbps > 0 {
			beacon = o.BeaconKbps
		}
		if minK == 0 || k < minK {
			minK = k
		}
	}
	if minK == 0 {
		return
	}
	if len(without) > 0 {
		note("%s: the minimum data rate is per radio in this driver and SSID(s) %q have none: the vendor's basic rates are kept", band, without)
		return
	}
	bm, low := basicRate(band, minK, noCCK)
	if bm == 0 {
		note("%s: minimum data rate %s Mb/s: no rate of the band meets it: the vendor's basic rates are kept", band, mbps(minK))
		return
	}
	rp.BasicRate = bm
	if len(asked) > 1 {
		slices.Sort(asked)
		note("%s: the minimum data rate is per radio in this driver: %s Mb/s for every SSID (asked: %v kbps)", band, mbps(low), asked)
	}
	note("%s: minimum data rate %s Mb/s is applied as the lowest basic rate (BasicRate=%d); the lower rates stay supported (the driver has no per-rate setting)", band, mbps(low), bm)
	if beacon > 0 && beacon != low {
		note("%s: beacon rate %s Mb/s not applied (the driver has no beacon-rate setting)", band, mbps(beacon))
	}
}

// basicRateKbps is the driver's BasicRate bitmap: bit i is this rate
// (Set_BasicRate_Proc, "BasicRateBitmap=0x%08lx"; the 2.4 GHz vendor value
// 351 = 1, 2, 5.5, 11, 6, 12 and 24 Mb/s).
var basicRateKbps = [12]int{1000, 2000, 5500, 11000, 6000, 9000, 12000, 18000, 24000, 36000, 48000, 54000}

const cckBits = 0xf // 1, 2, 5.5, 11 Mb/s

// defaultBasic are the basic rates kept at and above a minimum: the 2.4 GHz
// vendor set (351) and 802.11a's mandatory 6, 12 and 24 Mb/s on 5 GHz (the
// vendor's 5 GHz BasicRate=15 names only 802.11b rates, which that band
// does not have).
var defaultBasic = map[string]int{"ng": 351, "na": 1<<4 | 1<<6 | 1<<8}

// basicRate is the BasicRate bitmap for a minimum of kbps on band: the
// lowest rate of the band at or above kbps (low) plus the default basic
// rates above it, without the 802.11b ones when noCCK. 0 when no rate meets
// kbps. Basic rates are the ones every client must support: the result
// never adds an 802.11b rate the vendor's set does not already require, and
// adds at most one OFDM rate, which every 802.11g/n/ac client has.
func basicRate(band string, kbps int, noCCK bool) (bitmap, low int) {
	first := 0
	if band == "na" {
		first = 4 // OFDM only
	}
	lowBit := -1
	for i := first; i < len(basicRateKbps); i++ {
		if r := basicRateKbps[i]; r >= kbps && (lowBit < 0 || r < basicRateKbps[lowBit]) {
			lowBit = i
		}
	}
	if lowBit < 0 {
		return 0, 0
	}
	low = basicRateKbps[lowBit]
	for i, r := range basicRateKbps {
		if defaultBasic[band]&(1<<i) != 0 && r >= low {
			bitmap |= 1 << i
		}
	}
	if noCCK {
		bitmap &^= cckBits
	}
	return bitmap | 1<<lowBit, low
}

func mbps(kbps int) string { return strconv.FormatFloat(float64(kbps)/1000, 'f', -1, 64) }

// bandValue is m's value for band; the controller's keys may be "2g"/"5g".
func bandValue(m map[string]int, band string) int {
	for k, v := range m {
		if normBand(k) == band {
			return v
		}
	}
	return 0
}

func bandRateOpts(m map[string]bcmwifi.RateOpts, band string) bcmwifi.RateOpts {
	for k, v := range m {
		if normBand(k) == band {
			return v
		}
	}
	return bcmwifi.RateOpts{}
}

// profileFeatures adds rp's feature keys to kv (profile()).
func profileFeatures(kv map[string]string, base []byte, rd RadioDef, rp RadioPlan) {
	n := len(rd.Ifaces)
	var rrm, wnm, apsd []string
	for _, b := range rp.BSS {
		rrm, wnm, apsd = append(rrm, b01(b.RRM)), append(wnm, b01(b.BTM)), append(apsd, b01(b.UAPSD))
	}
	// per BSS in both drivers ("bDot11kRRMEnable[%d]", "bDot11vWNMEnable[%d]")
	kv["RRMEnable"] = listKey(base, "RRMEnable", n, rrm, "0")
	kv["WNMEnable"] = listKey(base, "WNMEnable", n, wnm, "0")
	if rd.UAPSD {
		// per BSS on the MT7663 ("APSDCapable[%d]=%d"); the MT7603 has none
		kv["APSDCapable"] = listKey(base, "APSDCapable", n, apsd, "0")
	}
	if rp.MinRSSI < 0 {
		kv["AssocReqRssiThres"] = listKey(nil, "AssocReqRssiThres", n, nil, strconv.Itoa(rp.MinRSSI))
	}
	if rp.DTIM > 0 {
		kv["DtimPeriod"] = strconv.Itoa(rp.DTIM)
	}
	if rp.BasicRate > 0 {
		kv["BasicRate"] = strconv.Itoa(rp.BasicRate)
	}
	if rp.IgmpSn {
		// the vendor's form: a ;-list on the MT7663, one value on the MT7603
		if cur, _ := getKey(base, "IgmpSnEnable"); strings.Contains(cur, ";") {
			kv["IgmpSnEnable"] = listKey(nil, "IgmpSnEnable", n, nil, "1")
		} else {
			kv["IgmpSnEnable"] = "1"
		}
	}
}
