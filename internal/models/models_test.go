// SPDX-License-Identifier: GPL-2.0-or-later

package models

import "testing"

func TestCatalog(t *testing.T) {
	m, ok := Lookup("u7pg2")
	if !ok || m.Display != "UniFi AP-AC-Pro" || m.Gen != 5 {
		t.Fatalf("%+v", m)
	}
	p := Profile(m)
	if p.Model != "U7PG2" || !p.Radios["na"].Is11ac || p.Radios["ng"].Is11ac {
		t.Fatalf("profile %+v", p)
	}
}

func TestSuggest(t *testing.T) {
	// the OnHub: 2.4 + 5 GHz, 3x3, Wi-Fi 5
	s := Suggest(AP{Bands: []string{"ng", "na"}, NSS: 3, Gen: 5})
	if s[0].Code != "U7MP" {
		t.Logf("top: %v", s[:3])
	}
	if s[0].Gen != 5 || s[0].Bands() != "ng+na" {
		t.Fatalf("top suggestion %v", s[0])
	}
	// a Wi-Fi 6 tri-band AP
	if s := Suggest(AP{Bands: []string{"ng", "na", "6e"}, NSS: 2, Gen: 6}); s[0].Gen != 6 || s[0].Bands() != "ng+na+6e" {
		t.Fatalf("6E top %v", s[0])
	}
}

func TestRearUplinkPort(t *testing.T) {
	for code, want := range map[string]int{"U6IW": 5, "U6ENTIW": 5, "U7IW": 3, "U7PG2": 0} {
		m, ok := Lookup(code)
		if !ok || m.RearUplinkPort() != want {
			t.Errorf("%s: RearUplinkPort = %d (found %v), want %d", code, m.RearUplinkPort(), ok, want)
		}
	}
}

// The Deco agent's U6-Lite words are a deliberate, reduced set
// (docs/deco/agent-design.md §3.5): WPA3, the fw_caps / fw3_caps bits that
// work in both modes, and each takeover feature's bit only with that
// feature (fw2_caps only with RadSec or the mDNS bridge); no hardware word,
// no DFS, 11ax ieee_modes.
func TestDecoAgentProfile(t *testing.T) {
	m, ok := Lookup("UAL6")
	if !ok {
		t.Fatal("UAL6 not in the catalogue")
	}
	p, ok := DecoAgentProfile(m, map[string]bool{"ng": true, "na": true})
	if !ok {
		t.Fatal("UAL6 refused")
	}
	if p.Model != "UAL6" || p.Display != "U6-Lite" || p.Version != "6.7.54.15663" {
		t.Errorf("identity %s %q %s", p.Model, p.Display, p.Version)
	}
	// observe mode (no features): WPA3; fw_caps adds encrypted syslog
	// (0x1000000) and SNMPv3 (0x4000), fw3_caps path monitoring (0x40), all
	// of which only read the unit or send ICMP echoes
	if p.WifiCaps != 131072 || p.WifiCaps2 != 0 || p.FWCaps != 0x1405403 || p.FW2Caps != 0 || p.FW3Caps != 0x40 {
		t.Errorf("words: wifi %d wifi2 %d fw %#x fw2 %d fw3 %#x", p.WifiCaps, p.WifiCaps2, p.FWCaps, p.FW2Caps, p.FW3Caps)
	}
	if p.WifiCaps&WifiCapRadiusMACAuth != 0 {
		t.Error("RADIUS MAC auth claimed: the driver-SME ACL check refuses every station with macaddr_acl=2")
	}
	// controller bit values (Network 11.1.50 device class support*())
	for name, c := range map[string][2]int64{
		"supportMinRateCtrl":       {WifiCapMinRateCtrl, 512},
		"supportRadiusMacAuth":     {WifiCapRadiusMACAuth, 4096},
		"supportWpaPpsk":           {WifiCapWPAPSKFile, 1048576},
		"supportLockAp":            {WifiCapLockAP, 16777216},
		"supportsAssistedRoaming":  {WifiCap2RoamAssist, 32},
		"supportSyslogEncryption":  {FWCapSyslogEncryption, 16777216},
		"supportsRadiusFilter":     {FWCapRadiusFilter, 536870912},
		"supportsSNMPv3":           {FWCapSNMPv3, 16384},
		"supportHotspot2":          {FWCapHotspot2, 8388608},
		"supportsRadSec":           {FW2CapRadSec, 524288},
		"supportsMdnsSdBridge":     {FW2CapMdnsSdBridge, 268435456},
		"supportsPathMonitoring":   {FW3CapPathMonitoring, 64},
		"supportsMulticastInspect": {FW3CapMulticastInspect, 128},
	} {
		if c[0] != c[1] {
			t.Errorf("%s: %#x, controller tests %#x", name, c[0], c[1])
		}
	}
	// each takeover feature adds exactly its bit
	for _, c := range []struct {
		f                         DecoAgentFeatures
		wifi, wifi2, fw, fw2, fw3 int64
	}{
		{DecoAgentFeatures{MinRate: true}, WifiCapMinRateCtrl, 0, 0, 0, 0},
		{DecoAgentFeatures{PPSK: true}, WifiCapWPAPSKFile, 0, 0, 0, 0},
		{DecoAgentFeatures{LockAP: true}, WifiCapLockAP, 0, 0, 0, 0},
		{DecoAgentFeatures{RoamAssist: true}, 0, WifiCap2RoamAssist, 0, 0, 0},
		{DecoAgentFeatures{RadiusFilter: true}, 0, 0, FWCapRadiusFilter, 0, 0},
		{DecoAgentFeatures{MulticastInspect: true}, 0, 0, 0, 0, FW3CapMulticastInspect},
		{DecoAgentFeatures{Hotspot2: true}, 0, 0, FWCapHotspot2, 0, 0},
		{DecoAgentFeatures{RadSec: true}, 0, 0, 0, FW2CapRadSec, 0},
		{DecoAgentFeatures{MdnsBridge: true}, 0, 0, 0, FW2CapMdnsSdBridge, 0},
	} {
		q, _ := DecoAgentProfileWith(m, nil, c.f)
		if q.WifiCaps != 131072|c.wifi || q.WifiCaps2 != c.wifi2 || q.FWCaps != 0x1405403|c.fw || q.FW3Caps != 0x40|c.fw3 || q.FW2Caps != c.fw2 {
			t.Errorf("%+v: wifi %#x wifi2 %#x fw %#x fw2 %#x fw3 %#x", c.f, q.WifiCaps, q.WifiCaps2, q.FWCaps, q.FW2Caps, q.FW3Caps)
		}
	}
	// the takeover masks cover every takeover-only bit, and nothing that
	// observe mode claims
	all, _ := DecoAgentProfileWith(m, nil, DecoAgentFeatures{RFScan: true, MinRate: true, PPSK: true, LockAP: true,
		RoamAssist: true, RadiusFilter: true, MulticastInspect: true, WPA3: true, RadSec: true, MdnsBridge: true, Hotspot2: true})
	if all.WifiCaps&^DecoAgentTakeoverWifiCaps != p.WifiCaps || all.WifiCaps2&^DecoAgentTakeoverWifiCaps2 != p.WifiCaps2 ||
		all.FWCaps&^DecoAgentTakeoverFWCaps != p.FWCaps || all.FW2Caps&^DecoAgentTakeoverFW2Caps != p.FW2Caps ||
		all.FW3Caps&^DecoAgentTakeoverFW3Caps != p.FW3Caps {
		t.Errorf("takeover masks: %+v vs observe %+v", all, p)
	}
	if p.WifiCaps&DecoAgentTakeoverWifiCaps != 0 || p.FWCaps&DecoAgentTakeoverFWCaps != 0 || p.FW2Caps&DecoAgentTakeoverFW2Caps != 0 ||
		p.FW3Caps&DecoAgentTakeoverFW3Caps != 0 {
		t.Error("an observe-mode bit is in a takeover mask")
	}
	ng, na := p.Radios["ng"], p.Radios["na"]
	if ng.IEEEModes != 90 || na.IEEEModes != 85 || ng.RadioCaps != RadioCapMIMO2 || na.RadioCaps != RadioCapMIMO2 ||
		ng.RadioCaps2 != 0 || na.RadioCaps2 != 0 || na.HasDFS || na.HasFCCDFS || ng.NSS != 2 || na.NSS != 2 {
		t.Errorf("radios ng %+v na %+v", ng, na)
	}
	// radio_caps2 WPA3 only with the wpa3 feature (config wpa3, takeover)
	if all.Radios["ng"].RadioCaps2 != RadioCap2WPA3 || all.Radios["na"].RadioCaps2 != RadioCap2WPA3 {
		t.Errorf("WPA3 feature: radios %+v", all.Radios)
	}
	if p, _ := DecoAgentProfile(m, map[string]bool{"ng": false, "na": false}); p.Radios["ng"].IEEEModes != 10 || p.Radios["na"].IEEEModes != 21 {
		t.Errorf("non-ax radios: %+v", p.Radios)
	}
	if p, _ := DecoAgentProfileWith(m, nil, DecoAgentFeatures{BandSteer: true}); p.WifiCaps != 131072|4 {
		t.Errorf("band steering: wifi_caps %d", p.WifiCaps)
	}
	// RF_SCAN only when the agent runs scans (takeover), never in observe
	if p, _ := DecoAgentProfileWith(m, nil, DecoAgentFeatures{RFScan: true}); p.WifiCaps != 131088 {
		t.Errorf("rf scan: wifi_caps %d", p.WifiCaps)
	}
	if p, _ := DecoAgentProfileWith(m, nil, DecoAgentFeatures{RFScan: true, BandSteer: true}); p.WifiCaps != 131092 {
		t.Errorf("takeover: wifi_caps %d", p.WifiCaps)
	}
	if u, _ := Lookup("U7PG2"); func() bool { _, ok := DecoAgentProfile(u, nil); return ok }() {
		t.Error("only UAL6 has agent words")
	}
}

func TestDecoAgentRadioCapsMIMO(t *testing.T) {
	m, ok := Lookup("UAL6")
	if !ok {
		t.Fatal("no UAL6")
	}
	p, ok := DecoAgentProfile(m, nil)
	if !ok {
		t.Fatal("no profile")
	}
	for _, b := range []string{"ng", "na"} {
		r := p.Radios[b]
		if r.NSS != 2 || r.RadioCaps != RadioCapMIMO2 {
			t.Errorf("%s: nss %d radio_caps %#x, want 2 and %#x (the UI's 2x2)", b, r.NSS, r.RadioCaps, RadioCapMIMO2)
		}
	}
	for nss, want := range map[int]int64{0: 0, 1: 0x8, 2: 0x10, 3: 0x20, 4: 0x4000000, 5: 0} {
		if got := RadioCapsMIMO(nss); got != want {
			t.Errorf("RadioCapsMIMO(%d) = %#x, want %#x", nss, got, want)
		}
	}
}

// TestU7LTAgentProfile: the JCOW414 reports as a UAP-AC-Lite: 802.11n and
// ac mode words, no WPA3 unless claimed.
func TestU7LTAgentProfile(t *testing.T) {
	m, ok := Lookup("U7LT")
	if !ok {
		t.Fatal("U7LT not in the catalogue")
	}
	heAX := map[string]bool{"ng": false, "na": false}
	p, ok := DecoAgentProfileWith(m, heAX, DecoAgentFeatures{})
	if !ok || p.WifiCaps&WifiCapWPA3 != 0 {
		t.Fatalf("profile ok=%v wifi_caps %#x", ok, p.WifiCaps)
	}
	if p.Radios["ng"].IEEEModes != decoAgentIEEEModesNGn || p.Radios["na"].IEEEModes != decoAgentIEEEModesNAn || !p.Radios["na"].Is11ac {
		t.Errorf("radios %+v", p.Radios)
	}
	p, _ = DecoAgentProfileWith(m, heAX, DecoAgentFeatures{WPA3: true})
	if p.WifiCaps&WifiCapWPA3 == 0 {
		t.Errorf("WPA3 feature not claimed")
	}
	// SAE is in the MT7663 (5 GHz) driver only
	if p.Radios["na"].RadioCaps2&RadioCap2WPA3 == 0 || p.Radios["ng"].RadioCaps2&RadioCap2WPA3 != 0 {
		t.Errorf("WPA3 radio caps: ng %#x na %#x", p.Radios["ng"].RadioCaps2, p.Radios["na"].RadioCaps2)
	}
}
