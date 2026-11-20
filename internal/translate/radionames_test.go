// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strconv"
	"strings"
	"testing"
)

func TestRadioNameBand(t *testing.T) {
	for name, want := range map[string]string{"wifi0": "ng", "ra0": "ng", "wifi1": "na", "rai0": "na", "wifi2": "6e"} {
		if got, ok := RadioNameBand(name); !ok || got != want {
			t.Errorf("RadioNameBand(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
	for _, name := range []string{"", "wifi3", "wifi00", "WIFI0", "ra1", "rai1", "ra", "wl0", "radio0"} {
		if got, ok := RadioNameBand(name); ok || got != "" {
			t.Errorf("RadioNameBand(%q) = %q, %v, want none", name, got, ok)
		}
	}
	for i, want := range []string{"wifi0", "wifi1", "wifi2", "wifi3"} {
		if got := PositionalRadioName(i); got != want {
			t.Errorf("PositionalRadioName(%d) = %q", i, got)
		}
	}
}

// The agent's intent takes the MediaTek names; the OpenWrt path (Plan,
// WLANs) takes the positional names only, as it always did: there ra0 and
// rai0 are no 2.4 GHz hint and name no band.
func TestRadioNamesByPath(t *testing.T) {
	for name, want := range map[string]string{"wifi0": "ng", "wifi1": "na", "wifi2": "6e", "ra0": "", "rai0": "", "wifi3": "", "": ""} {
		if got, ok := qcaRadioBand(name); got != want || ok != (want != "") {
			t.Errorf("qcaRadioBand(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}

	// a WLAN whose parent no radio section names
	for parent, want := range map[string]string{"wifi0": "2g", "wifi1": "5g", "wifi2": "6g", "ra0": "", "rai0": "", "wifi3": ""} {
		ws := WLANs(Cfg{"wireless.1.ssid": "home", "wireless.1.parent": parent})
		if len(ws) != 1 || ws[0].Band != want {
			t.Errorf("WLANs: parent %q on band %q, want %q", parent, ws[0].Band, want)
		}
		in, notes := IntentFrom(Cfg{"wireless.1.ssid": "home", "wireless.1.parent": parent, "wireless.1.id": "w1"})
		bands := ""
		if len(in.WLANs) == 1 {
			bands = strings.Join(in.WLANs[0].Bands, ",")
		}
		wantIntent := map[string]string{"wifi0": "ng", "wifi1": "na", "wifi2": "6e", "ra0": "ng", "rai0": "na", "wifi3": ""}[parent]
		if bands != wantIntent {
			t.Errorf("IntentFrom: parent %q on %q, want %q (%q)", parent, bands, wantIntent, notes)
		}
	}

	// a radio section whose ieee_mode names no band: the name decides
	for phy, c := range map[string]struct{ openwrt, intent string }{
		"wifi0": {"2g", "ng"}, "wifi1": {"5g", "na"}, "ra0": {"5g", "ng"}, "rai0": {"5g", "na"},
	} {
		cfg := Cfg{"radio.1.phyname": phy, "radio.1.ieee_mode": "11ax", "wireless.1.ssid": "home",
			"wireless.1.parent": phy, "wireless.1.id": "w1"}
		if ws := WLANs(cfg); len(ws) != 1 || ws[0].Band != c.openwrt {
			t.Errorf("WLANs: radio %q on band %q, want %q", phy, ws[0].Band, c.openwrt)
		}
		in, _ := IntentFrom(cfg)
		if _, ok := in.Radios[c.intent]; !ok || len(in.Radios) != 1 {
			t.Errorf("IntentFrom: radio %q gives radios %v, want %q", phy, in.Radios, c.intent)
		}
		// an AP with a 2.4 GHz radio only: Plan misses the 5 GHz one
		r := Plan(cfg, UCI{"wireless.radio0": "wifi-device", "wireless.radio0.band": "2g"}, Features{})
		miss := strings.Contains(strings.Join(r.Notes, "\n"), "no 5g radio on this AP")
		if miss != (c.openwrt == "5g") {
			t.Errorf("Plan: radio %q, want band %s: %q", phy, c.openwrt, r.Notes)
		}
	}
}

// The channel width is read from ieee_mode twice: htmode (the OpenWrt
// path, by suffix) and widthRe (the agent's intent, by pattern). They are
// not one parser, since they differ on the forms at the end of this test;
// for the modes a controller sends for a 2.4 or 5 GHz radio they agree.
func TestIEEEModeWidths(t *testing.T) {
	for mode, want := range map[string]int{
		"11nght20": 20, "11nght40": 40,
		"11naht20": 20, "11naht40": 40, "11naht80": 80, "11naht160": 160,
		"11acvht20": 20, "11acvht40": 40, "11acvht80": 80, "11acvht160": 160,
		"11axhe20": 20, "11axhe40": 40, "11axhe80": 80, "11axhe160": 160,
	} {
		ht := strings.TrimLeft(htmode(mode, ""), "HEVT")
		if got, _ := strconv.Atoi(ht); got != want {
			t.Errorf("htmode(%q) = %q, want width %d", mode, htmode(mode, ""), want)
		}
		m := widthRe.FindStringSubmatch(mode)
		if m == nil {
			t.Errorf("widthRe does not match %q", mode)
			continue
		}
		if got, _ := strconv.Atoi(m[1]); got != want {
			t.Errorf("widthRe on %q = %s, want %d", mode, m[1], want)
		}
	}
	// where they differ: a width followed by a suffix, and no width at all
	if got := htmode("11axhe160_6e", ""); got != "HE20" {
		t.Errorf("htmode(11axhe160_6e) = %q", got)
	}
	if m := widthRe.FindStringSubmatch("11axhe160_6e"); m == nil || m[1] != "160" {
		t.Errorf("widthRe on 11axhe160_6e = %v", m)
	}
	if got := htmode("11ax", ""); got != "HT20" {
		t.Errorf("htmode(11ax) = %q", got)
	}
	if m := widthRe.FindStringSubmatch("11ax"); m != nil {
		t.Errorf("widthRe on 11ax = %v", m)
	}
}
