// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"fmt"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// The feature keys of the vendor profiles as read on the unit (2026-11-19).
const (
	featNG = "RRMEnable=0;1;0;0\nWNMEnable=1;1;1;1\nAPSDCapable=0\nDtimPeriod=2\nBasicRate=351\nIgmpSnEnable=1\n"
	featNA = "RRMEnable=0;1;0;0\nWNMEnable=1;1;1;1\nAPSDCapable=0\nDtimPeriod=2\nBasicRate=15\nIgmpSnEnable=1;1;1;1\n"
)

func baseNG() []byte { return []byte(baseDat + featNG) }
func baseNA() []byte {
	return []byte(strings.Replace(baseDat, "MaxStaNum", "MbssMaxStaNum", 1) + featNA)
}

// twoSSIDs: one dual-band WPA2 SSID and one 2.4 GHz open one.
func twoSSIDs() bcmwifi.Desired {
	return bcmwifi.Desired{
		Radios: map[string]bcmwifi.Radio{"ng": {Enabled: true, Channel: 6, Width: 20}, "na": {Enabled: true, Channel: 36, Width: 80}},
		SSIDs: []bcmwifi.SSID{
			{ID: "a", SSID: "home", Bands: []string{"2g", "5g"}, Enabled: true, Security: "wpa2", Passphrase: "secret-home"},
			{ID: "b", SSID: "iot", Bands: []string{"2g"}, Enabled: true, Security: "open"},
		},
	}
}

func joined(notes []string) string { return strings.Join(notes, "\n") }

func wantKeys(t *testing.T, what string, p []byte, want map[string]string) {
	t.Helper()
	for k, v := range want {
		got, ok := getKey(p, k)
		if v == "" && ok {
			t.Errorf("%s: %s written (%q), want the key left out", what, k, got)
		} else if v != "" && got != v {
			t.Errorf("%s: %s = %q, want %q", what, k, got, v)
		}
	}
}

// TestRadiusMACAuthNotServed: an SSID asking for RADIUS MAC authentication
// is never served (it would be open to every station), on any band, and
// is noted once.
func TestRadiusMACAuthNotServed(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs[0].Radius = &bcmwifi.Radius{MACAuth: true, Auth: []bcmwifi.RadiusServer{{IP: "192.168.0.9", Port: 1812, Secret: "radius-secret"}}}
	ps, notes := plans(d, JCOW414, false)
	for band, rp := range ps {
		for _, b := range rp.BSS {
			if b.ID == "a" {
				t.Errorf("%s: MAC-auth SSID served: %+v", band, b)
			}
		}
	}
	if ps["na"].On {
		t.Errorf("na on with its only SSID refused: %+v", ps["na"])
	}
	if len(ps["ng"].BSS) != 1 || ps["ng"].BSS[0].ID != "b" {
		t.Errorf("ng %+v", ps["ng"].BSS)
	}
	j := joined(notes)
	if strings.Count(j, `SSID "home": RADIUS MAC authentication is not supported by this driver: not served`) != 1 {
		t.Errorf("notes %q", notes)
	}
	if strings.Contains(j, "radius-secret") || strings.Contains(j, "secret-home") {
		t.Error("secret in notes")
	}
	// without MAC auth (RADIUS accounting only) it is served as before
	d.SSIDs[0].Radius.MACAuth = false
	if ps, _ := plans(d, JCOW414, false); len(ps["na"].BSS) != 1 {
		t.Errorf("RADIUS without MAC auth refused: %+v", ps["na"])
	}
}

// TestNotCarriedNotes: what the controller asks for and this unit does not
// apply is noted; the SSID is still served.
func TestNotCarriedNotes(t *testing.T) {
	d := twoSSIDs()
	s := &d.SSIDs[0]
	s.PSKs = []bcmwifi.PSK{{}}
	s.RateLimit = &bcmwifi.RateLimit{DownKbps: 5000, UpKbps: 1000}
	s.ProxyARP = true
	s.Hotspot2 = &bcmwifi.Hotspot2{}
	s.FT = true
	s.UAPSD = true
	s.PMF = "optional"
	ps, notes := plans(d, JCOW414, false)
	if len(ps["ng"].BSS) != 2 || len(ps["na"].BSS) != 1 {
		t.Fatalf("SSID not served: ng %+v na %+v", ps["ng"].BSS, ps["na"].BSS)
	}
	j := joined(notes)
	for _, want := range []string{
		`SSID "home": private pre-shared keys (PPSK) are not supported`,
		`SSID "home": per-client rate limit (down 5000, up 1000 kbit/s) not applied`,
		`SSID "home": proxy ARP not applied`,
		`SSID "home": Hotspot 2.0 is not advertised`,
		`ng: SSID "home": 802.11r is not supported by the MT7603E driver`,
		`na: SSID "home": 802.11r is not applied`,
		`ng: SSID "home": U-APSD is not supported by the MT7603E driver`,
		`ng: SSID "home": PMF optional not applied: served with PMF disabled`,
	} {
		if !strings.Contains(j, want) {
			t.Errorf("missing note %q in\n%s", want, j)
		}
	}
	// WPA2 with PMF optional is served as asked on 5 GHz (the MT7663 has
	// PMF): no note there
	if b := ps["na"].BSS[0]; b.PMF != 1 {
		t.Errorf("na PMF %d, want 1 (optional)", b.PMF)
	}
	if strings.Contains(j, `na: SSID "home": PMF`) {
		t.Errorf("PMF noted on 5 GHz")
	}
	// SSID-wide notes once, not per band
	if strings.Count(j, "proxy ARP") != 1 {
		t.Errorf("proxy ARP noted %d times", strings.Count(j, "proxy ARP"))
	}
	// U-APSD is carried on 5 GHz: no note there
	if strings.Contains(j, `na: SSID "home": U-APSD`) {
		t.Errorf("U-APSD noted on 5 GHz")
	}
	// nothing asked, nothing noted (beyond the per-radio IGMP note)
	_, notes = plans(twoSSIDs(), JCOW414, false)
	for _, n := range notes {
		if !strings.Contains(n, "multicast enhancement off") {
			t.Errorf("unexpected note %q", n)
		}
	}
}

// TestPMFNoteWPA3: WPA2/WPA3 on 5 GHz serves PMF optional; required asked
// is noted, optional asked is not.
func TestPMFNoteWPA3(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs[0].Security, d.SSIDs[0].PMF = "wpa2wpa3", "optional"
	_, notes := plans(d, JCOW414, true)
	if j := joined(notes); strings.Contains(j, `na: SSID "home": PMF`) {
		t.Errorf("PMF optional noted on WPA2/WPA3: %q", notes)
	}
	d.SSIDs[0].PMF = "required"
	_, notes = plans(d, JCOW414, true)
	if j := joined(notes); !strings.Contains(j, `na: SSID "home": PMF required not applied: served with PMF optional`) {
		t.Errorf("notes %q", notes)
	}
}

// TestRRMAndWNM: 802.11k and 802.11v follow each SSID per BSS; the vendor
// values (RRM 0;1;0;0, WNM 1;1;1;1) no longer leak through for the served
// slots.
func TestRRMAndWNM(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs[0].RRM, d.SSIDs[0].BSSTransition = true, false
	d.SSIDs[1].RRM, d.SSIDs[1].BSSTransition = false, true
	ps, notes := plans(d, JCOW414, false)
	ng := ps["ng"]
	if !ng.BSS[0].RRM || ng.BSS[0].BTM || ng.BSS[1].RRM || !ng.BSS[1].BTM {
		t.Errorf("ng BSS %+v", ng.BSS)
	}
	wantKeys(t, "ng", profile(baseNG(), JCOW414[0], ng), map[string]string{"RRMEnable": "1;0;0;0", "WNMEnable": "0;1;1;1"})
	wantKeys(t, "na", profile(baseNA(), JCOW414[1], ps["na"]), map[string]string{"RRMEnable": "1;1;0;0", "WNMEnable": "0;1;1;1"})
	if !strings.Contains(joined(notes), "ng: 802.11k is advertised, but no neighbour list is configured") {
		t.Errorf("notes %q", notes)
	}
	// all off: slot 2 (served) no longer advertises RRM
	d.SSIDs[0].RRM, d.SSIDs[1].BSSTransition = false, false
	ps, _ = plans(d, JCOW414, false)
	wantKeys(t, "ng off", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"RRMEnable": "0;0;0;0", "WNMEnable": "0;0;1;1"})
}

// TestMinRSSI: neither driver reads AssocReqRssiThres from the profile
// (in mt7603eap.ko and the MT7663 kernel driver it is only an entry of the
// iwpriv set table, Set_AP_ASSOC_REQ_RSSI_THRESHOLD; the profile parsers
// never reference the string), so writing it would change nothing but
// restart the radio. The minimum RSSI is noted as not applied, the key is
// never written and the plan does not change with it.
func TestMinRSSI(t *testing.T) {
	d := twoSSIDs()
	ps0, _ := plans(d, JCOW414, false)
	for _, v := range []int{-75, -101, 5} {
		d.Radios["ng"] = bcmwifi.Radio{Enabled: true, Channel: 6, Width: 20, MinRSSI: v}
		ps, notes := plans(d, JCOW414, false)
		if ps["ng"].hash() != ps0["ng"].hash() {
			t.Errorf("MinRSSI %d changes the plan (a radio restart for nothing)", v)
		}
		wantKeys(t, "ng", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"AssocReqRssiThres": ""})
		if j := joined(notes); !strings.Contains(j, fmt.Sprintf("ng: minimum RSSI %d dBm not applied", v)) ||
			strings.Contains(j, "refuses associations") {
			t.Errorf("MinRSSI %d: notes %q", v, notes)
		}
	}
}

// TestDTIM: one DtimPeriod per radio, the lowest the SSIDs ask, noted when
// they differ; none asked keeps the vendor's.
func TestDTIM(t *testing.T) {
	d := twoSSIDs()
	ps, _ := plans(d, JCOW414, false)
	if ps["ng"].DTIM != 0 {
		t.Errorf("DTIM %d without a setting", ps["ng"].DTIM)
	}
	wantKeys(t, "vendor", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"DtimPeriod": "2"})
	d.SSIDs[0].DTIM = map[string]int{"ng": 3, "na": 1}
	d.SSIDs[1].DTIM = map[string]int{"2g": 1}
	ps, notes := plans(d, JCOW414, false)
	if ps["ng"].DTIM != 1 || ps["na"].DTIM != 1 {
		t.Errorf("DTIM ng %d na %d", ps["ng"].DTIM, ps["na"].DTIM)
	}
	wantKeys(t, "ng", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"DtimPeriod": "1"})
	j := joined(notes)
	if !strings.Contains(j, "ng: DTIM is one value per radio in this driver: 1 for every SSID (asked: [1 3])") || strings.Contains(j, "na: DTIM") {
		t.Errorf("notes %q", notes)
	}
}

// TestUAPSD: per BSS on 5 GHz (APSDCapable list); the 2.4 GHz driver has no
// U-APSD, so its profile key stays the vendor's.
func TestUAPSD(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs[0].UAPSD = true
	d.SSIDs = append(d.SSIDs, bcmwifi.SSID{ID: "c", SSID: "five", Bands: []string{"5g"}, Enabled: true, Security: "wpa2", Passphrase: "secret-five"})
	ps, _ := plans(d, JCOW414, false)
	if ps["ng"].BSS[0].UAPSD {
		t.Errorf("U-APSD planned on 2.4 GHz")
	}
	if !ps["na"].BSS[0].UAPSD || ps["na"].BSS[1].UAPSD {
		t.Errorf("na BSS %+v", ps["na"].BSS)
	}
	wantKeys(t, "na", profile(baseNA(), JCOW414[1], ps["na"]), map[string]string{"APSDCapable": "1;0;0;0"})
	wantKeys(t, "ng", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"APSDCapable": "0"})
}

func TestBasicRateBitmap(t *testing.T) {
	for _, c := range []struct {
		band          string
		kbps          int
		noCCK         bool
		bitmap, lowKb int
	}{
		{"ng", 1000, false, 351, 1000}, // the vendor's set
		{"ng", 2000, false, 350, 2000},
		{"ng", 5500, false, 348, 5500},
		{"ng", 6000, false, 344, 6000}, // 11 Mb/s CCK stays basic
		{"ng", 6000, true, 336, 6000},
		{"ng", 9000, false, 360, 9000},
		{"ng", 12000, true, 320, 12000},
		{"ng", 18000, false, 384, 18000},
		{"ng", 54000, false, 2048, 54000},
		{"ng", 55000, false, 0, 0},
	} {
		bm, low := basicRate(c.kbps, c.noCCK)
		if bm != c.bitmap || low != c.lowKb {
			t.Errorf("basicRate(%s, %d, %t) = %d, %d; want %d, %d", c.band, c.kbps, c.noCCK, bm, low, c.bitmap, c.lowKb)
		}
		if bm != 0 && bm&(1<<12-1) != bm {
			t.Errorf("bitmap %d beyond the driver's 12 rates", bm)
		}
	}
}

// TestMinRate: BasicRate only when every SSID of the radio has a minimum
// (the lowest of them); otherwise the vendor's value stays. 5 GHz never:
// both drivers' UpdateBasicRateBitmap clears the 802.11b bits and ORs in
// 0x150 (6, 12 and 24 Mb/s) whenever the channel is above 14, so no
// BasicRate can raise the lowest basic rate there.
func TestMinRate(t *testing.T) {
	d := twoSSIDs()
	ps, _ := plans(d, JCOW414, false)
	wantKeys(t, "no minimum", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"BasicRate": "351"})
	wantKeys(t, "no minimum", profile(baseNA(), JCOW414[1], ps["na"]), map[string]string{"BasicRate": "15"})
	na0 := ps["na"]

	// one SSID of two with a minimum: per radio, so the vendor's is kept
	d.SSIDs[0].MinRateKbps = map[string]int{"ng": 12000, "na": 24000}
	d.SSIDs[0].MinRateOpts = map[string]bcmwifi.RateOpts{"ng": {BeaconKbps: 12000, NoCCK: true}, "na": {BeaconKbps: 24000}}
	ps, notes := plans(d, JCOW414, false)
	if ps["ng"].BasicRate != 0 {
		t.Errorf("ng BasicRate %d with an SSID without a minimum", ps["ng"].BasicRate)
	}
	// 5 GHz: noted, the vendor's BasicRate kept, no radio restart
	if ps["na"].BasicRate != 0 || ps["na"].hash() != na0.hash() {
		t.Errorf("na BasicRate %d (plan changed: %t)", ps["na"].BasicRate, ps["na"].hash() != na0.hash())
	}
	wantKeys(t, "na", profile(baseNA(), JCOW414[1], ps["na"]), map[string]string{"BasicRate": "15"})
	j := joined(notes)
	if !strings.Contains(j, `ng: the minimum data rate is per radio in this driver and SSID(s) ["iot"] have none`) ||
		!strings.Contains(j, "na: minimum data rate 24 Mb/s not applied") ||
		strings.Contains(j, "na: minimum data rate 24 Mb/s is applied") ||
		strings.Contains(j, "beacon rate") {
		t.Errorf("notes %q", notes)
	}

	// both: the lowest; CCK basic rates only off when every SSID drops them
	d.SSIDs[1].MinRateKbps = map[string]int{"2g": 6000}
	d.SSIDs[1].MinRateOpts = map[string]bcmwifi.RateOpts{"2g": {BeaconKbps: 11000}}
	ps, notes = plans(d, JCOW414, false)
	if ps["ng"].BasicRate != 344 {
		t.Errorf("ng BasicRate %d, want 344 (6 Mb/s with CCK 11 basic)", ps["ng"].BasicRate)
	}
	wantKeys(t, "ng", profile(baseNG(), JCOW414[0], ps["ng"]), map[string]string{"BasicRate": "344"})
	j = joined(notes)
	if !strings.Contains(j, "ng: the minimum data rate is per radio in this driver: 6 Mb/s for every SSID (asked: [6000 12000] kbps)") ||
		!strings.Contains(j, "ng: beacon rate 11 Mb/s not applied") {
		t.Errorf("notes %q", notes)
	}

	// no rate meets it
	d.SSIDs[0].MinRateKbps["ng"] = 60000
	d.SSIDs[1].MinRateKbps["2g"] = 60000
	ps, notes = plans(d, JCOW414, false)
	if ps["ng"].BasicRate != 0 || !strings.Contains(joined(notes), "ng: minimum data rate 60 Mb/s: no rate of the band meets it") {
		t.Errorf("ng %d notes %q", ps["ng"].BasicRate, notes)
	}
}

// TestIgmpSnooping: on when an SSID asks for multicast enhancement, in the
// vendor's form per driver; never written as 0.
func TestIgmpSnooping(t *testing.T) {
	d := twoSSIDs()
	ps, notes := plans(d, JCOW414, false)
	if ps["ng"].IgmpSn || ps["na"].IgmpSn {
		t.Errorf("IGMP snooping planned without an SSID asking")
	}
	off := strings.Replace(featNG, "IgmpSnEnable=1", "IgmpSnEnable=0", 1)
	wantKeys(t, "off", profile([]byte(baseDat+off), JCOW414[0], ps["ng"]), map[string]string{"IgmpSnEnable": "0"})
	if !strings.Contains(joined(notes), "ng: multicast enhancement off: IGMP snooping stays as the vendor set it") {
		t.Errorf("notes %q", notes)
	}
	d.SSIDs[0].MulticastToUnicast = true
	ps, notes = plans(d, JCOW414, false)
	if !ps["ng"].IgmpSn || !ps["na"].IgmpSn {
		t.Errorf("IGMP snooping ng %t na %t", ps["ng"].IgmpSn, ps["na"].IgmpSn)
	}
	wantKeys(t, "ng", profile([]byte(baseDat+off), JCOW414[0], ps["ng"]), map[string]string{"IgmpSnEnable": "1"})
	naOff := strings.Replace(featNA, "IgmpSnEnable=1;1;1;1", "IgmpSnEnable=0;0;0;0", 1)
	wantKeys(t, "na", profile([]byte(baseDat+naOff), JCOW414[1], ps["na"]), map[string]string{"IgmpSnEnable": "1;1;1;1"})
	j := joined(notes)
	if !strings.Contains(j, `ng: multicast enhancement (IGMP snooping) is per radio in this driver: on for every SSID (asked by ["home"])`) ||
		strings.Contains(j, "na: multicast enhancement") {
		t.Errorf("notes %q", notes)
	}
}

// TestFeaturesStructural: every new setting is in the profile only, so a
// change restarts the radio; Hidden/Isolate/MaxSta stay live.
func TestFeaturesStructural(t *testing.T) {
	ps, _ := plans(twoSSIDs(), JCOW414, false)
	base := ps["ng"]
	mut := map[string]func(*RadioPlan){
		"RRM":       func(r *RadioPlan) { r.BSS[0].RRM = !r.BSS[0].RRM },
		"BTM":       func(r *RadioPlan) { r.BSS[0].BTM = !r.BSS[0].BTM },
		"UAPSD":     func(r *RadioPlan) { r.BSS[0].UAPSD = !r.BSS[0].UAPSD },
		"DTIM":      func(r *RadioPlan) { r.DTIM = 3 },
		"BasicRate": func(r *RadioPlan) { r.BasicRate = 344 },
		"IgmpSn":    func(r *RadioPlan) { r.IgmpSn = true },
	}
	for name, f := range mut {
		c := base
		c.BSS = append([]BSS(nil), base.BSS...)
		f(&c)
		if c.structural() == base.structural() {
			t.Errorf("%s change is not structural", name)
		}
	}
	c := base
	c.BSS = append([]BSS(nil), base.BSS...)
	c.BSS[0].Hidden = true
	if c.structural() != base.structural() || c.hash() == base.hash() {
		t.Errorf("Hidden is no longer live-only")
	}
}

// TestFeaturesRadioOff: a radio that is off carries none of the per-radio
// settings (no spurious plan difference).
func TestFeaturesRadioOff(t *testing.T) {
	d := twoSSIDs()
	d.Radios["na"] = bcmwifi.Radio{Enabled: false}
	d.SSIDs[0].DTIM = map[string]int{"na": 3}
	d.SSIDs[0].MulticastToUnicast = true
	ps, _ := plans(d, JCOW414, false)
	if na := ps["na"]; na.On || na.DTIM != 0 || na.IgmpSn || na.BasicRate != 0 || len(na.BSS) != 0 {
		t.Errorf("na off: %+v", na)
	}
}

// TestOldLastGood: a last-good plan saved before these settings existed
// writes the vendor's values for them (and never IGMP snooping off).
func TestOldLastGood(t *testing.T) {
	rp := RadioPlan{Band: "ng", On: true, Channel: 6, Width: 20, TxPct: 100,
		BSS: []BSS{{ID: "a", SSID: "home", Auth: "WPA2PSK", Encr: "AES", PSK: "secret-home", MaxSta: 32}}}
	wantKeys(t, "old", profile(baseNG(), JCOW414[0], rp), map[string]string{"DtimPeriod": "2", "BasicRate": "351",
		"IgmpSnEnable": "1", "AssocReqRssiThres": ""})
}
