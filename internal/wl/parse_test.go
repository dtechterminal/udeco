// SPDX-License-Identifier: GPL-2.0-or-later

package wl

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/apstate"
)

func TestDecodeChanspec(t *testing.T) {
	for _, tc := range []struct {
		cs                     uint16
		band                   string
		control, center, width int
		ok                     bool
	}{
		{0x1804, "ng", 2, 4, 40, true},   // "2l"
		{0x1905, "ng", 7, 5, 40, true},   // "7u"
		{0x1809, "ng", 7, 9, 40, true},   // "7l"
		{0x1002, "ng", 2, 2, 20, true},   // "2"
		{0xe22a, "na", 44, 42, 80, true}, // "44/80"
		{0xe12a, "na", 40, 42, 80, true}, // "40/80"
		{0xe02a, "na", 36, 42, 80, true}, // "36/80"
		{0xe39b, "na", 161, 155, 80, true},
		{0xd02c, "na", 44, 44, 20, true},
		{0xd926, "na", 40, 38, 40, true}, // "40u"
		{0x0000, "", 0, 0, 0, false},
		{0x8024, "", 0, 0, 0, false}, // 4.9 GHz band
		{0xc024, "", 0, 0, 0, false}, // no width
	} {
		got, ok := decodeChanspec(tc.cs)
		if ok != tc.ok {
			t.Errorf("%#x: ok=%v", tc.cs, ok)
			continue
		}
		if ok && (got.Band != tc.band || got.Control != tc.control || got.Center != tc.center || got.Width != tc.width) {
			t.Errorf("%#x = %+v", tc.cs, got)
		}
	}
}

func TestParseChanspecString(t *testing.T) {
	for _, tc := range []struct {
		s, band                string
		control, center, width int
	}{
		{"6", "ng", 6, 6, 20},
		{"7u", "ng", 7, 5, 40},
		{"8u", "ng", 8, 6, 40},
		{"1l", "ng", 1, 3, 40},
		{"44l", "na", 44, 46, 40},
		{"36/80", "na", 36, 42, 80},
		{"161/80", "na", 161, 155, 80},
		{"100/160", "na", 100, 114, 160},
	} {
		got, ok := parseChanspecString(tc.s, tc.band)
		if !ok || got.Control != tc.control || got.Center != tc.center || got.Width != tc.width {
			t.Errorf("%q = %+v, %v", tc.s, got, ok)
		}
	}
	for _, bad := range []string{"", "x", "36/x", "0"} {
		if _, ok := parseChanspecString(bad, "na"); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseChanspecFixtures(t *testing.T) {
	for _, tc := range []struct {
		file     string
		raw      uint16
		ch, wid  int
		wantBand string
	}{
		{"wl_-i_wl0_chanspec.txt", 0x1804, 2, 40, "ng"},
		{"wl_-i_wl1_chanspec.txt", 0xe22a, 44, 80, "na"},
	} {
		cs, ok := parseChanspecHex(string(fixture(t, tc.file)))
		if !ok || cs.Raw != tc.raw || cs.Control != tc.ch || cs.Width != tc.wid || cs.Band != tc.wantBand {
			t.Errorf("%s = %+v %v", tc.file, cs, ok)
		}
	}
}

func TestScalarParsers(t *testing.T) {
	intCases := []struct {
		file string
		want int64
	}{
		{"wl_-i_wl0_noise.txt", -98},
		{"wl_-i_wl1_noise.txt", -94},
		{"wl_-i_wl0_hw_txchain.txt", 3},
		{"wl_-i_wl0_vhtmode.txt", 1},
		{"wl_-i_wl0_bw_cap_2g.txt", 3},
		{"wl_-i_wl1_bw_cap_5g.txt", 7},
		{"wl_-i_wl01_dwds.txt", 1},
		{"wl_-i_wl02_dwds.txt", 0},
	}
	for _, tc := range intCases {
		if n, ok := parseInt(fixture(t, tc.file)); !ok || n != tc.want {
			t.Errorf("%s = %d %v, want %d", tc.file, n, ok, tc.want)
		}
	}
	if _, ok := parseInt(nil); ok {
		t.Error("empty input parsed")
	}

	for file, want := range map[string]string{
		"wl_-i_wl02_ssid.txt": "Example Network",
		"wl_-i_wl13_ssid.txt": "olive#",
		"wl_-i_wl0_ssid.txt":  "",
	} {
		if got := parseSSID(fixture(t, file)); got != want {
			t.Errorf("%s = %q, want %q", file, got, want)
		}
	}
	// wl escapes only backslashes and non-printable bytes; quotes stay as is
	if got := parseSSID([]byte(`Current SSID: "a\\b\x01"q"`)); got != "a\\b\x01\"q" {
		t.Errorf("escaped SSID = %q", got)
	}

	for in, want := range map[string]string{
		string(fixture(t, "wl_-i_wl02_wpa_auth.txt")): "psk+sae",
		string(fixture(t, "wl_-i_wl01_wpa_auth.txt")): "psk",
		"0x0 Disabled":     "none",
		"0x40 WPA2-802.1x": "8021x",
		"garbage":          "",
	} {
		if got := parseWPAAuth([]byte(in)); got != want {
			t.Errorf("wpa_auth %q = %q, want %q", in, got, want)
		}
	}

	if got := parseCountry(fixture(t, "wl_-i_wl0_country.txt")); got != "US" {
		t.Errorf("country = %q", got)
	}
	capSet := parseCap(fixture(t, "wl_-i_wl0_cap.txt"))
	if !capSet["11ax"] || !capSet["dwds"] || maxBSS(capSet) != 8 {
		t.Errorf("cap: 11ax=%v dwds=%v mbss=%d", capSet["11ax"], capSet["dwds"], maxBSS(capSet))
	}
	if maxBSS(parseCap([]byte("ap sta"))) != 1 {
		t.Error("maxBSS default")
	}
	if got := parseRevinfo(fixture(t, "wl_-i_wl0_revinfo.txt")); got != "Broadcom BCM4491" {
		t.Errorf("revinfo = %q", got)
	}
	if got := parseRevinfo(fixture(t, "wl_-i_wl1_revinfo.txt")); got != "Broadcom BCM4492" {
		t.Errorf("revinfo wl1 = %q", got)
	}
}

func TestParseTxpwr(t *testing.T) {
	for file, want := range map[string]float64{
		"wl_-i_wl0_txpwr_target_max.txt": 24,
		"wl_-i_wl1_txpwr_target_max.txt": 23.5,
	} {
		if v, ok := parseTxpwrTargetMax(fixture(t, file)); !ok || v != want {
			t.Errorf("%s = %v %v", file, v, ok)
		}
	}
	if _, ok := parseTxpwrTargetMax([]byte("Maximum Tx Power Target (chanspec:0x1804):")); ok {
		t.Error("no values parsed")
	}
	m0 := parseChanspecTxpwrMax(fixture(t, "wl_-i_wl0_chanspec_txpwr_max.txt"))
	if len(m0) != 25 || m0[0x1804] != 25.5 {
		t.Errorf("wl0 chanspec_txpwr_max: %d rows, 0x1804=%v", len(m0), m0[0x1804])
	}
	m1 := parseChanspecTxpwrMax(fixture(t, "wl_-i_wl1_chanspec_txpwr_max.txt"))
	if m1[0xe22a] != 25 {
		t.Errorf("wl1 0xe22a = %v", m1[0xe22a])
	}
}

func TestChanspecsList(t *testing.T) {
	ng := channelsByWidth(parseChanspecs(fixture(t, "wl_-i_wl0_chanspecs.txt")))
	eleven := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	if !reflect.DeepEqual(ng, map[int][]int{20: eleven, 40: eleven}) {
		t.Errorf("ng channels = %v", ng)
	}
	na := channelsByWidth(parseChanspecs(fixture(t, "wl_-i_wl1_chanspecs.txt")))
	want := map[int][]int{
		20: {36, 40, 44, 48, 149, 153, 157, 161, 165},
		40: {36, 40, 44, 48, 149, 153, 157, 161},
		80: {36, 40, 44, 48, 149, 153, 157, 161},
	}
	if !reflect.DeepEqual(na, want) {
		t.Errorf("na channels = %v", na)
	}
}

func TestParseChanimUs(t *testing.T) {
	for _, tc := range []struct {
		file string
		want chanimRow
	}{
		{"wl_-i_wl0_chanim_stats_us.txt", chanimRow{Key: 0x1002, Tx: 1256523294, Inbss: 47640412, Busy: 4302164810, Total: 13480070000}},
		{"wl_-i_wl1_chanim_stats_us.txt", chanimRow{Key: 0xd02c, Tx: 438300558, Inbss: 57283710, Busy: 956998667, Total: 13496999000}},
	} {
		got, ok := parseChanimUs(fixture(t, tc.file))
		if !ok || got != tc.want {
			t.Errorf("%s = %+v %v", tc.file, got, ok)
		}
	}
	// after a radio re-init: values past 2^63 (ParseInt would fail)
	row := "chanspec  tx  inbss  obss  nocat  nopkt  doze  txop  goodtx  badtx  total_tm  busy_tm\n" +
		"0xd028  4374030349  4304458611  4369489479  4331325009  4297818699  0  8427552872433558289  4316992788  4300034752  18446739785199950616  4418189910\n"
	got, ok := parseChanimUs([]byte(row))
	if !ok || got.Total != 18446739785199950616 || got.Busy != 4418189910 {
		t.Errorf("offset row = %+v %v", got, ok)
	}
	for _, bad := range []string{"", "version: 3\n", "chanspec tx\n0x1002 x\n", "0x1002 1 2 3\n"} {
		if _, ok := parseChanimUs([]byte(bad)); ok {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestParseStaInfoAll(t *testing.T) {
	sta := parseStaInfoAll(fixture(t, "wl_-i_wl12_sta_info_all.txt"))
	if len(sta) != 3 {
		t.Fatalf("got %d stations", len(sta))
	}
	want := apstate.Station{
		MAC: "d2:f7:e5:58:6f:89", Signal: -78, SignalAvg: -78, Noise: -95,
		Inactive: 0, Connected: 75, Authorized: true,
		RxBytes: 225800, TxBytes: 287611, RxPackets: 1007, TxPackets: 663,
		RxRate: 288230, TxRate: 272220, TxRetries: 193, TxFailed: 0,
		HT: true, VHT: true, HE: true, MHz: 80, NSS: 2,
	}
	if sta[0] != want {
		t.Errorf("station 0 =\n%+v\nwant\n%+v", sta[0], want)
	}
	if s := sta[1]; s.MAC != "a6:7b:63:9f:25:40" || s.TxFailed != 2 || s.Inactive != 1000 || s.RxRate != 6000 {
		t.Errorf("station 1 = %+v", s)
	}
	if s := sta[2]; s.HE || !s.VHT || s.Connected != 13559 || s.Signal != -70 || s.SignalAvg != -70 {
		t.Errorf("station 2 = %+v", s)
	}

	// every client of every VAP fixture parses, and matches assoclist
	for _, vap := range []string{"wl02", "wl12", "wl13"} {
		sta := parseStaInfoAll(fixture(t, "wl_-i_"+vap+"_sta_info_all.txt"))
		assoc := strings.Fields(strings.ToLower(string(fixture(t, "wl_-i_"+vap+"_assoclist.txt"))))
		var macs []string
		for _, s := range sta {
			macs = append(macs, s.MAC)
			if s.Signal >= 0 || s.Connected <= 0 || s.MHz == 0 || !s.Authorized || s.TxRate <= 0 {
				t.Errorf("%s %s: implausible %+v", vap, s.MAC, s)
			}
		}
		var want []string
		for _, f := range assoc {
			if f != "assoclist" {
				want = append(want, f)
			}
		}
		if !sameSet(macs, want) {
			t.Errorf("%s: sta_info %v, assoclist %v", vap, macs, want)
		}
	}
	// the per-MAC form is the same block format
	one := parseStaInfoAll(fixture(t, "wl_-i_wl02_sta_info_8CBFEA1DBA74.txt"))
	if len(one) != 1 || one[0].MAC != "8c:bf:ea:1d:ba:74" || one[0].Signal == 0 {
		t.Errorf("per-MAC = %+v", one)
	}
	if got := parseStaInfoAll(fixture(t, "wl_-i_wl01_sta_info_all.txt")); len(got) != 0 {
		t.Errorf("empty VAP: %v", got)
	}

	// an older layout without smoothed rssi / retry exhausted / link bandwidth
	old := "STA 00:11:22:33:44:55:\n\t chanspec 36/80 (0xe02a)\n\t tx failures: 4\n" +
		"\t per antenna average rssi of rx data frames: -60 -55 0 0\n\t state: AUTHENTICATED ASSOCIATED\n"
	got := parseStaInfoAll([]byte(old))
	if len(got) != 1 || got[0].Signal != -55 || got[0].TxFailed != 4 || got[0].MHz != 80 || got[0].Authorized {
		t.Errorf("old layout = %+v", got)
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestParseScanResults(t *testing.T) {
	bss := parseScanResults(fixture(t, "wl_-i_wl0_scanresults_populated.txt"), "ng")
	if len(bss) != 25 {
		t.Fatalf("got %d BSSes", len(bss))
	}
	esp := bss[0]
	if esp.SSID != "ESP_36CB75" || esp.BSSID != "8c:bf:ea:1d:ba:75" || esp.Signal != -62 ||
		esp.Channel != 7 || esp.Width != 40 || esp.Freq != 2442 || esp.CenterFreq != 2432 || esp.Security != "Open" {
		t.Errorf("ESP = %+v", esp)
	}
	d := bss[1]
	if d.SSID != "Example Network" || d.Security != "WPA2+WPA3-Personal (AES/CCMP)" || d.Channel != 8 || d.Signal != -53 {
		t.Errorf("D Tech = %+v", d)
	}
	if bss[2].SSID != "" || bss[2].Security != "WPA2-Personal (AES/CCMP)" {
		t.Errorf("hidden = %+v", bss[2])
	}
	for _, b := range bss {
		if b.Channel < 1 || b.Channel > 13 || b.Freq < 2412 || b.Signal >= 0 || len(b.BSSID) != 17 {
			t.Errorf("implausible %+v", b)
		}
	}

	// 5 GHz, no Chanspec line: fall back to "Channel:"; WEP; enterprise
	in := "SSID: \"five\"\nMode: Managed\tRSSI: -70 dBm\tSNR: 20 dB\tnoise: -92 dBm\tFlags: RSSI on-channel \tChannel: 36/80\n" +
		"BSSID: 00:11:22:33:44:55\tCapability: ESS Privacy\n" +
		"SSID: \"wep\"\nMode: Managed\tRSSI: -80 dBm\tChannel: 6\nBSSID: 00:11:22:33:44:56\tCapability: ESS WEP\n" +
		"SSID: \"corp\"\nMode: Managed\tRSSI: -75 dBm\tChannel: 44l\nBSSID: 00:11:22:33:44:57\tCapability: ESS WEP\n" +
		"RSN (WPA2):\n\tAKM Suites(1): WPA2-802.1x\n" +
		"SSID: \"nobssid\"\n"
	got := parseScanResults([]byte(in), "na")
	if len(got) != 3 {
		t.Fatalf("got %+v", got)
	}
	if got[0].Channel != 36 || got[0].Width != 80 || got[0].CenterFreq != 5210 || got[0].Freq != 5180 || got[0].Security != "WEP" {
		t.Errorf("five = %+v", got[0])
	}
	if got[2].Security != "WPA2-Enterprise" || got[2].Channel != 44 || got[2].Width != 40 {
		t.Errorf("corp = %+v", got[2])
	}
}

// sta_info all also lists the driver's leftover record of a station that
// left (empty state, idle 1178 s, RSSI 0; .205 2026-11-19, MACs replaced):
// only the associated one is a station.
func TestParseStaInfoAllSkipsLeftover(t *testing.T) {
	sta := parseStaInfoAll(fixture(t, "wl_-i_wl12_sta_info_all_leftover.txt"))
	if len(sta) != 1 || sta[0].MAC != "02:00:00:00:0e:02" || sta[0].Signal == 0 {
		t.Fatalf("stations %+v", sta)
	}
}
