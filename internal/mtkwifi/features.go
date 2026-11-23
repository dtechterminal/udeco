// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"slices"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/rf"
	"github.com/dtechterminal/udeco/internal/translate"
)

// The controller's per-SSID and per-radio features beyond the BSS list.
//
// Every one is written to the driver profile (profile()), so a change
// restarts the radio: structural() keeps them. The drivers have them per
// BSS (RRMEnable, WNMEnable, APSDCapable on the MT7663) or per radio only
// (DtimPeriod, BasicRate; IgmpSnEnable on the MT7603); a per-SSID setting the driver has
// per radio is folded (DTIM: the lowest; minimum rate: only when every SSID
// of the radio has one, 2.4 GHz only) with a note. What the
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
			note("SSID %q: per-client rate limit (down %d, up %d kbit/s) not applied"+rlOffSuffix, s.SSID, r.DownKbps, r.UpKbps)
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
	if s.UAPSD && !rd.UAPSD {
		note("%s: SSID %q: U-APSD is not supported by the %s driver", rd.Band, s.SSID, rd.HWName)
	}
	if want := pmfLevel(s.PMF); b.Auth != "OPEN" && want > b.PMF {
		note("%s: SSID %q: PMF %s not applied: served with PMF %s", rd.Band, s.SSID, s.PMF, translate.PMFWord(b.PMF))
	}
	// The BSS Load element: the drivers' QBSS load is radio-wide, on while
	// any BSS has WMM (forced on by HT) or 802.11k (MT7603 ap_qload.c
	// QBSS_LoadInit), with no profile key or command to turn it off
	if s.NoBSSLoad {
		note("%s: SSID %q: BSS Load element off is not applied: the %s driver advertises it on every BSS of the radio", rd.Band, s.SSID, rd.HWName)
	}
}

// pmfLevel is translate.PMFLevel, with any other word (and "") as off.
func pmfLevel(p string) int { return max(translate.PMFLevel(p), 0) }

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

	for _, b := range rp.BSS {
		if b.RRM && !rd.FT {
			// with FT served the agent keeps the neighbour lists (roam.go:
			// NrAdd on the MT7603, its own answers on the MT7663)
			note("%s: 802.11k is advertised; neighbour reports come from the driver's own scan table (the agent's neighbour lists need ft%s)", band, ft2GWhy(rd))
			break
		}
	}

	// IGMP snooping (the driver's multicast-to-unicast). The MT7663 has
	// it per BSS (IgmpSnEnable=a;b;c;d): each SSID follows the
	// controller (BSS.M2U), as the U6's per-VAP mcastenhance. The MT7603
	// has one value per radio, on in the vendor's profile: turned on when
	// an SSID asks, never off (off sends multicast at the 1 Mb/s basic
	// rate to every SSID of the radio)
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
	case perBSSIgmp(rd):
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
// keeps the vendor's basic rates for the whole radio. Never on 5 GHz: both
// drivers' UpdateBasicRateBitmap, for a channel above 14, clears the
// 802.11b bits and ORs in 6, 12 and 24 Mb/s (0x150), so 6 Mb/s stays the
// lowest basic rate whatever BasicRate says.
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
	if band != "ng" {
		note("%s: minimum data rate %s Mb/s not applied (the driver always keeps 6, 12 and 24 Mb/s as basic rates on 5 GHz)", band, mbps(minK))
		return
	}
	if len(without) > 0 {
		note("%s: the minimum data rate is per radio in this driver and SSID(s) %q have none: the vendor's basic rates are kept", band, without)
		return
	}
	bm, low := basicRate(minK, noCCK)
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

// defaultBasic are the 2.4 GHz basic rates kept at and above a minimum:
// the vendor set (351).
const defaultBasic = 351

// basicRate is the 2.4 GHz BasicRate bitmap for a minimum of kbps: the
// lowest rate at or above kbps (low) plus the default basic rates above it,
// without the 802.11b ones when noCCK. 0 when no rate meets kbps. Basic
// rates are the ones every client must support: the result never adds an
// 802.11b rate the vendor's set does not already require, and adds at most
// one OFDM rate, which every 802.11g/n client has.
func basicRate(kbps int, noCCK bool) (bitmap, low int) {
	lowBit := -1
	for i := range basicRateKbps {
		if r := basicRateKbps[i]; r >= kbps && (lowBit < 0 || r < basicRateKbps[lowBit]) {
			lowBit = i
		}
	}
	if lowBit < 0 {
		return 0, 0
	}
	low = basicRateKbps[lowBit]
	for i, r := range basicRateKbps {
		if defaultBasic&(1<<i) != 0 && r >= low {
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
		if rf.Norm(k) == band {
			return v
		}
	}
	return 0
}

func bandRateOpts(m map[string]bcmwifi.RateOpts, band string) bcmwifi.RateOpts {
	for k, v := range m {
		if rf.Norm(k) == band {
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
	kv["RRMEnable"] = slotKey(base, "RRMEnable", n, rp, rrm, "0")
	kv["WNMEnable"] = slotKey(base, "WNMEnable", n, rp, wnm, "0")
	if rd.UAPSD {
		// per BSS on the MT7663 ("APSDCapable[%d]=%d"); the MT7603 has none
		kv["APSDCapable"] = slotKey(base, "APSDCapable", n, rp, apsd, "0")
	}
	if rp.DTIM > 0 {
		kv["DtimPeriod"] = strconv.Itoa(rp.DTIM)
	}
	if rp.BasicRate > 0 {
		kv["BasicRate"] = strconv.Itoa(rp.BasicRate)
	}
	switch {
	case perBSSIgmp(rd):
		var m2u []string
		for _, b := range rp.BSS {
			m2u = append(m2u, b01(b.M2U))
		}
		kv["IgmpSnEnable"] = slotKey(base, "IgmpSnEnable", n, rp, m2u, "1")
	case rp.IgmpSn:
		// the vendor's form: one value on the MT7603
		if cur, _ := getKey(base, "IgmpSnEnable"); strings.Contains(cur, ";") {
			kv["IgmpSnEnable"] = listKey(nil, "IgmpSnEnable", n, nil, "1")
		} else {
			kv["IgmpSnEnable"] = "1"
		}
	}
	ftKeys(kv, base, rd, rp) // roam.go
	u6Defaults(kv, base, rd, rp)
}

// perBSSIgmp: the radio's driver has IgmpSnEnable per BSS (the MT7663).
func perBSSIgmp(rd RadioDef) bool { return rd.Band == "na" }

// acsSkip24 are the 2.4 GHz channels automatic channel selection skips:
// all of the unit's (chans24) but 1, 6 and 11 (rf.NonOverlap24), as the U6
// (radio.conf `block_acs_channel -band 1 2,3,4,5,7,8,9,10,...`; 12-14 are
// outside this unit's channel list). In the profile's form: "2;3;4;...".
var acsSkip24 = skipList(chans24, rf.NonOverlap24())

// skipList is all without keep as an AutoChannelSkipList value.
func skipList(all, keep []int) string {
	var skip []string
	for _, ch := range all {
		if !slices.Contains(keep, ch) {
			skip = append(skip, strconv.Itoa(ch))
		}
	}
	return strings.Join(skip, ";")
}

// pmkCacheMinutes is the 5 GHz PMK cache lifetime (PMKCachePeriod,
// minutes): hostapd's default 12 h, so an idle SAE phone resumes with
// its PMKSA instead of a new SAE after the vendor's 10 minutes.
const pmkCacheMinutes = "720"

// u6Defaults adds the settings a U6 applies whatever the controller says,
// and the per-BSS group rekey the controller sends, to kv. Each is a
// profile key (read when the radio comes up), so they ride the restart
// the first deploy makes anyway (adopt compares the whole profile).
func u6Defaults(kv map[string]string, base []byte, rd RadioDef, rp RadioPlan) {
	n := len(rd.Ifaces)
	all := func(v string) string { return listKey(nil, "", n, nil, v) }
	// WPS: the U6 runs wps_state=disabled; the vendor's profiles have the
	// registrar on (WscConfMode=4) for every slot
	kv["WscConfMode"] = all("0")
	// the vendor's band steering flag: inert without its daemon (stopped),
	// and the agent claims no band steering
	kv["BandSteering"] = all("0")
	// GTK rekey as the controller asks, per served BSS; open never rekeys
	var method, interval []string
	for _, b := range rp.BSS {
		if b.GroupRekey > 0 && b.Auth != "OPEN" {
			method, interval = append(method, "TIME"), append(interval, strconv.Itoa(b.GroupRekey))
		} else {
			method, interval = append(method, "DISABLE"), append(interval, "0")
		}
	}
	kv["RekeyMethod"] = slotKey(base, "RekeyMethod", n, rp, method, "TIME")
	kv["RekeyInterval"] = slotKey(base, "RekeyInterval", n, rp, interval, "3600")
	switch rd.Band {
	case "ng":
		// 20/40 coexistence off (U6 disablecoext 1, cwmenable 0)
		kv["HT_BSSCoexistence"] = "0"
		if rp.Channel == 0 {
			kv["AutoChannelSkipList"] = acsSkip24
		}
	case "na":
		// implicit beamforming off (U6 implicitbf 0); explicit stays
		kv["ITxBfEn"] = "0"
		// the driver's station events on rtnetlink (events_linux.go)
		kv["WirelessEvent"] = "1"
		kv["PMKCachePeriod"] = pmkCacheMinutes
	}
}
