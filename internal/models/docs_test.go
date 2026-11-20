// SPDX-License-Identifier: GPL-2.0-or-later

package models

import (
	"fmt"
	"math/bits"
	"strings"
	"testing"
	"unicode"

	"github.com/dtechterminal/udeco/internal/inform"
	"github.com/dtechterminal/udeco/internal/repotest"
)

// Tests that hold the documents to this package: the capability table and
// its result paragraph in docs/deco/agent-design.md, the feature notes that
// name a bit, and the catalogue's size in docs/internals.md. The documents
// keep their prose; a constant or a claim that changes here fails until
// the document says the same.

const (
	agentDesign = "docs/deco/agent-design.md"
	agentSource = "internal/models/agent.go"
)

// capRow is one row of agent-design.md's capability table.
type capRow struct {
	bits    []string // the bit cell's entries: "2", "7", "11", "0x400"
	name    string
	claimed string
}

// capTable reads the table under "UAL6 capability words": word -> rows. A
// row with an empty first cell belongs to the word above it.
func capTable(t *testing.T) map[string][]capRow {
	t.Helper()
	doc := repotest.Read(t, agentDesign)
	_, sec, ok := strings.Cut(doc, "\n#### UAL6 capability words (`models.DecoAgentProfile`)\n")
	if !ok {
		t.Fatalf("%s has no capability words section", agentDesign)
	}
	sec, _, ok = strings.Cut(sec, "\nResult (")
	if !ok {
		t.Fatalf("%s: no Result paragraph after the capability table", agentDesign)
	}
	out := map[string][]capRow{}
	word := ""
	for _, l := range strings.Split(sec, "\n") {
		if !strings.HasPrefix(l, "|") {
			continue
		}
		c := strings.Split(l, "|")
		if len(c) < 6 {
			t.Fatalf("%s: capability table row with %d cells: %.60s", agentDesign, len(c)-2, l)
		}
		w := strings.TrimSpace(c[1])
		if w == "word" || strings.HasPrefix(w, "---") {
			continue
		}
		if w != "" {
			word = w
		}
		r := capRow{name: strings.TrimSpace(c[3]), claimed: strings.TrimSpace(c[4])}
		for _, b := range strings.Split(c[2], ",") {
			r.bits = append(r.bits, strings.TrimSpace(b))
		}
		out[word] = append(out[word], r)
	}
	return out
}

// decoObserve and decoTakeover are the features cmd/udeco-ap gives
// DecoAgentProfileWith on a Deco with none of the optional config keys
// (min_rates, wpa3, hotspot2, mdns_bridge): nothing in observe mode; in
// takeover what bcmwifi and the agent always do there (agent.go setup).
// cmd/udeco-ap's end-to-end tests hold the words the agent informs to the
// same paragraph (docsCapabilityWords).
var (
	decoObserve  = DecoAgentFeatures{}
	decoTakeover = DecoAgentFeatures{BandSteer: true, RFScan: true, PPSK: true, LockAP: true, RoamAssist: true,
		RadiusFilter: true, MulticastInspect: true, RadSec: true, DFS: true}
)

func decoProfile(t *testing.T, f DecoAgentFeatures) inform.Profile {
	t.Helper()
	m, ok := Lookup(DecoAgentModel)
	if !ok {
		t.Fatalf("%s is not in the catalogue", DecoAgentModel)
	}
	p, ok := DecoAgentProfileWith(m, nil, f)
	if !ok {
		t.Fatalf("%s has no agent profile", DecoAgentModel)
	}
	return p
}

// Every capability bit agent.go names has its row in the table, under its
// word and with the claim the code makes: yes for a bit the observe-mode
// profile has, takeover for one that needs the agent to own Wi-Fi, no for
// one that is named only to say why it is not claimed.
func TestDocsCapabilityTable(t *testing.T) {
	table := capTable(t)
	consts := repotest.IntConsts(t, agentSource)
	// the constants as read from the source are the compiled ones
	for name, v := range map[string]int64{"WifiCapLockAP": WifiCapLockAP, "FWCapSNMPv3": FWCapSNMPv3, "FW2CapMdnsSdBridge": FW2CapMdnsSdBridge,
		"RadioCap2WPA3FT": RadioCap2WPA3FT, "DecoAgentTakeoverWifiCaps": DecoAgentTakeoverWifiCaps} {
		if got, ok := consts[name]; !ok || got != v {
			t.Fatalf("%s reads %s as %#x (found %v), it is %#x", agentSource, name, got, ok, v)
		}
	}

	obs := decoProfile(t, decoObserve)
	observe := map[string]int64{"wifi_caps": obs.WifiCaps, "wifi_caps2": obs.WifiCaps2, "fw_caps": obs.FWCaps,
		"fw2_caps": obs.FW2Caps, "fw3_caps": obs.FW3Caps, "radio_caps2": obs.Radios["na"].RadioCaps2 | obs.Radios["ng"].RadioCaps2}
	// what a drop to observe clears (cmd/udeco-ap agent.fields): the
	// masks, and SAE per radio. BANDSTEER is not in its mask on purpose
	// (it stays claimed until the agent restarts, as the Result paragraph
	// says), and only a backend that steers, which takes takeover, sets it.
	takeover := map[string]int64{"wifi_caps": DecoAgentTakeoverWifiCaps | WifiCapBandSteer, "wifi_caps2": DecoAgentTakeoverWifiCaps2,
		"fw_caps": DecoAgentTakeoverFWCaps, "fw2_caps": DecoAgentTakeoverFW2Caps, "fw3_caps": DecoAgentTakeoverFW3Caps,
		"radio_caps2": RadioCap2WPA3 | RadioCap2WPA3FT}

	// a constant's word by its name; the longer prefixes first
	kinds := []struct {
		prefix, word string
		asBit        bool // the table gives the bit's number, not its value
	}{
		{"WifiCap2", "wifi_caps2", false},
		{"WifiCap", "wifi_caps", true},
		{"FW2Cap", "fw2_caps", false},
		{"FW3Cap", "fw3_caps", false},
		{"FWCap", "fw_caps", false},
		{"RadioCap2", "radio_caps2", false},
	}
	checked := 0
	for name, v := range consts {
		if !unicode.IsUpper(rune(name[0])) || strings.HasPrefix(name, "DecoAgent") || !strings.Contains(name, "Cap") {
			continue
		}
		if strings.HasPrefix(name, "RadioCapMIMO") {
			continue // the radio_caps row names the function (below)
		}
		word, asBit := "", false
		for _, k := range kinds {
			if strings.HasPrefix(name, k.prefix) {
				word, asBit = k.word, k.asBit
				break
			}
		}
		if word == "" {
			t.Errorf("%s: %s is a capability constant of no word this test knows: add its word here and its row to %s", agentSource, name, agentDesign)
			continue
		}
		if bits.OnesCount64(uint64(v)) != 1 {
			t.Errorf("%s = %#x is not one bit", name, v)
			continue
		}
		want := fmt.Sprintf("%#x", v)
		if asBit {
			want = fmt.Sprint(bits.TrailingZeros64(uint64(v)))
		}
		var row *capRow
		for i, r := range table[word] {
			for _, b := range r.bits {
				if b == want {
					row = &table[word][i]
				}
			}
		}
		if row == nil {
			t.Errorf("%s: the %s rows have none for %s (%s)", agentDesign, word, name, want)
			continue
		}
		checked++
		claim := "no"
		switch {
		case observe[word]&v != 0:
			claim = "**yes**"
		case takeover[word]&v != 0:
			claim = "**takeover"
		}
		if !strings.HasPrefix(row.claimed, claim) {
			t.Errorf("%s: %s %s (%s, %s) is claimed %q in the table; by the code it starts with %q", agentDesign, word, want, name, row.name, row.claimed, claim)
		}
	}
	if checked < 20 {
		t.Errorf("%d capability constants checked against the table: the source or the table was not read", checked)
	}

	// rows that give no bit value of their own
	one := func(word string) capRow {
		if len(table[word]) != 1 {
			t.Fatalf("%s: %d rows for %q, want one", agentDesign, len(table[word]), word)
		}
		return table[word][0]
	}
	if r := one("radio ieee_modes"); strings.Join(r.bits, ", ") != fmt.Sprintf("ng %d, na %d", decoAgentIEEEModesNG, decoAgentIEEEModesNA) {
		t.Errorf("%s: radio ieee_modes row has %q, the code %d and %d", agentDesign, r.bits, decoAgentIEEEModesNG, decoAgentIEEEModesNA)
	}
	repotest.MustHave(t, agentDesign,
		"| radio_caps | MIMO bit | 1x1..4x4 | yes | `models.RadioCapsMIMO`;",
		fmt.Sprintf("a non-HE radio gets the U7PG2 %d/%d |", nonAXIEEEModes("ng"), nonAXIEEEModes("na")))
	// has_dfs: with the DFS feature, on 5 GHz only, never in observe mode
	take := decoProfile(t, decoTakeover)
	if obs.Radios["na"].HasDFS || !take.Radios["na"].HasDFS || !take.Radios["na"].HasFCCDFS || take.Radios["ng"].HasDFS {
		t.Errorf("has_dfs: observe na %v, takeover na %v ng %v", obs.Radios["na"].HasDFS, take.Radios["na"].HasDFS, take.Radios["ng"].HasDFS)
	}
	if r := one("has_dfs, has_fccdfs"); !strings.HasPrefix(r.claimed, "**takeover only**, on the 5 GHz radio") {
		t.Errorf("%s: has_dfs row is claimed %q", agentDesign, r.claimed)
	}
	// the switch bits: only with PortVLAN, and only on a model with LAN ports
	iw, _ := Lookup(ModelUHDIW)
	ports, _ := DecoAgentProfileWith(iw, nil, DecoAgentFeatures{PortVLAN: true})
	deco := decoProfile(t, DecoAgentFeatures{PortVLAN: true})
	if sw := int64(FWCapQCASwitch | FWCapOWRTSwitch); ports.FWCaps&sw != sw || deco.FWCaps&sw != 0 {
		t.Errorf("switch bits: %s with PortVLAN %#x, %s with PortVLAN %#x", ModelUHDIW, ports.FWCaps, DecoAgentModel, deco.FWCaps)
	}
	for _, r := range table["fw_caps"] {
		if (r.bits[0] == fmt.Sprintf("%#x", FWCapQCASwitch) || r.bits[0] == fmt.Sprintf("%#x", FWCapOWRTSwitch)) &&
			r.claimed != "**takeover only**, on a model with LAN ports" {
			t.Errorf("%s: fw_caps %s is claimed %q", agentDesign, r.bits[0], r.claimed)
		}
	}
}

// The Result paragraph under the table quotes the words of both modes as
// the profile computes them.
func TestDocsCapabilityResult(t *testing.T) {
	obs, take := decoProfile(t, decoObserve), decoProfile(t, decoTakeover)
	// what the paragraph says each word is made of
	if obs.WifiCaps != WifiCapWPA3 || obs.WifiCaps2 != 0 || obs.FW2Caps != 0 || obs.FW3Caps != FW3CapPathMonitoring ||
		obs.FWCaps != inform.PlaceholderFWCaps|FWCapSHA512SSH|FWCapSNMPv3|FWCapWlanScheduleMultiBlock|FWCapWlanScheduleInvert|FWCapSyslogEncryption {
		t.Errorf("observe: %+v: reword the Result paragraph and this test", obs)
	}
	if take.WifiCaps != WifiCapWPA3|WifiCapRFScan|WifiCapBandSteer|WifiCapWPAPSKFile|WifiCapLockAP || take.WifiCaps2 != WifiCap2RoamAssist ||
		take.FWCaps != obs.FWCaps|FWCapRadiusFilter || take.FW2Caps != FW2CapRadSec || take.FW3Caps != obs.FW3Caps|FW3CapMulticastInspect {
		t.Errorf("takeover: %+v: reword the Result paragraph and this test", take)
	}
	wpa3 := decoProfile(t, DecoAgentFeatures{WPA3: true})
	if wpa3.Radios["ng"].RadioCaps2 != wpa3.Radios["na"].RadioCaps2 || take.Radios["na"].RadioCaps2 != 0 {
		t.Errorf("radio_caps2: with wpa3 ng %#x na %#x, without %#x", wpa3.Radios["ng"].RadioCaps2, wpa3.Radios["na"].RadioCaps2, take.Radios["na"].RadioCaps2)
	}
	repotest.MustHave(t, agentDesign,
		fmt.Sprintf("Observe mode: `wifi_caps %d` (WPA3), `fw_caps %#x` (placeholder bits, SHA-512 SSH, SNMPv3, the two schedule bits, encrypted syslog), `fw3_caps %#x` (path monitoring), no wifi_caps2/fw2_caps/hw_caps.",
			obs.WifiCaps, obs.FWCaps, obs.FW3Caps),
		fmt.Sprintf("Takeover: `wifi_caps %d` (%#x: WPA3 | RF_SCAN | BANDSTEER | WPA_PSK_FILE | LOCK_AP, plus MINRATE_CTRL %#x with `min_rates`), `wifi_caps2 %#x` (Roaming Assistant), `fw_caps %#x` (+ RADIUS filter; + Hotspot 2.0 %#x with `hotspot2`), `fw2_caps %#x` (RadSec; + mDNS bridge %#x with `apply` and `mdns_bridge`), `fw3_caps %#x` (+ multicast inspect), radio_caps2 %#x on both radios with `wpa3` (else 0).",
			take.WifiCaps, take.WifiCaps, WifiCapMinRateCtrl, take.WifiCaps2, take.FWCaps, FWCapHotspot2, take.FW2Caps, FW2CapMdnsSdBridge, take.FW3Caps, wpa3.Radios["na"].RadioCaps2))
}

// The feature notes that name a capability bit give its value and say
// whether it is claimed. Each phrase is the note's own sentence with the
// value taken from the constant; the condition beside it is the claim the
// sentence makes, read from the code.
func TestDocsFeatureNoteBits(t *testing.T) {
	obs, take := decoProfile(t, decoObserve), decoProfile(t, decoTakeover)
	bit := func(v int64) int { return bits.TrailingZeros64(uint64(v)) }
	const notes = "docs/deco/features/"
	for _, c := range []struct {
		rel, phrase string
		holds       bool // the claim the phrase makes
	}{
		{notes + "lock-to-ap.md", fmt.Sprintf("# Lock to Access Point (wifi_caps %#x)", WifiCapLockAP), true},
		{notes + "lock-to-ap.md", "The bit is claimed in takeover only (`models.WifiCapLockAP`, one of `models.DecoAgentTakeoverWifiCaps`;",
			DecoAgentTakeoverWifiCaps&WifiCapLockAP != 0 && obs.WifiCaps&WifiCapLockAP == 0 && take.WifiCaps&WifiCapLockAP != 0},
		{notes + "lock-to-ap.md", fmt.Sprintf("`wifi_caps` bit %d (%#x, `supportLockAp`): **takeover only**", bit(WifiCapLockAP), WifiCapLockAP), true},
		{notes + "radius-macauth-hs20-radsec.md", fmt.Sprintf("## RADIUS MAC authentication (wifi_caps %#x, `supportRadiusMacAuth`)", WifiCapRadiusMACAuth), true},
		{notes + "radius-macauth-hs20-radsec.md", "RADIUS MAC authentication is still not claimed (`models.WifiCapRadiusMACAuth`).",
			(obs.WifiCaps|take.WifiCaps|DecoAgentTakeoverWifiCaps)&WifiCapRadiusMACAuth == 0},
		{notes + "radius-macauth-hs20-radsec.md", fmt.Sprintf("## Hotspot 2.0 (fw_caps %#x, `supportHotspot2`)", FWCapHotspot2), true},
		{notes + "radius-macauth-hs20-radsec.md", "Hotspot 2.0 in takeover with the `hotspot2` key (`models.FWCapHotspot2`,",
			DecoAgentTakeoverFWCaps&FWCapHotspot2 != 0 && take.FWCaps&FWCapHotspot2 == 0 && decoProfile(t, DecoAgentFeatures{Hotspot2: true}).FWCaps&FWCapHotspot2 != 0},
		{notes + "radius-macauth-hs20-radsec.md", fmt.Sprintf("## RadSec (fw2_caps %#x, `supportsRadSec`)", FW2CapRadSec), true},
		{notes + "radius-macauth-hs20-radsec.md", "RadSec is claimed in takeover (`models.FW2CapRadSec`,",
			DecoAgentTakeoverFW2Caps&FW2CapRadSec != 0 && obs.FW2Caps == 0 && take.FW2Caps&FW2CapRadSec != 0},
		{notes + "radsec.md", fmt.Sprintf("Capability: fw2_caps `%#x` (`supportsRadSec`, `hasFirmware2Capability(%d)`", FW2CapRadSec, FW2CapRadSec), true},
		{notes + "hotspot2.md", fmt.Sprintf("capability bit (fw_caps %#x) is claimed only in takeover mode with the config key `hotspot2`", FWCapHotspot2), true},
		{notes + "hotspot2.md", fmt.Sprintf("Capability: **fw_caps %#x** (`supportHotspot2` = `hasFirmwareCapability(%d)`", FWCapHotspot2, FWCapHotspot2), true},
		{notes + "mdns-bridge.md", fmt.Sprintf("# mDNS service bridge (fw2_caps %#x)", FW2CapMdnsSdBridge), true},
		{notes + "mdns-bridge.md", fmt.Sprintf("Claimed (fw2_caps %#x) only in takeover with `apply` and the config key `mdns_bridge`", FW2CapMdnsSdBridge),
			DecoAgentTakeoverFW2Caps&FW2CapMdnsSdBridge != 0 && take.FW2Caps&FW2CapMdnsSdBridge == 0},
		{notes + "mdns-bridge.md", fmt.Sprintf("With `supportsMdnsSdBridge` (fw2_caps bit %d, %#x) set", bit(FW2CapMdnsSdBridge), FW2CapMdnsSdBridge), true},
		{notes + "multicast-inspect.md", fmt.Sprintf("| multicast inspect | fw3_caps | %#x | `supportsMulticastInspect` |", FW3CapMulticastInspect), true},
		{notes + "multicast-inspect.md", fmt.Sprintf("| mDNS service bridge | fw2_caps | %#x | `supportsMdnsSdBridge` |", FW2CapMdnsSdBridge), true},
		{notes + "multicast-inspect.md", fmt.Sprintf("Bit: fw3_caps %#x, claimed in takeover only (`models.FW3CapMulticastInspect`, one of `models.DecoAgentTakeoverFW3Caps`).", FW3CapMulticastInspect),
			DecoAgentTakeoverFW3Caps&FW3CapMulticastInspect != 0 && obs.FW3Caps&FW3CapMulticastInspect == 0 && take.FW3Caps&FW3CapMulticastInspect != 0},
		{notes + "multicast-inspect.md", "the agent's wifi_caps2 word, sent for the Roaming Assistant in takeover, never has this bit",
			obs.WifiCaps2 == 0 && take.WifiCaps2 == WifiCap2RoamAssist && DecoAgentTakeoverWifiCaps2 == WifiCap2RoamAssist},
		{notes + "pathmon.md", fmt.Sprintf("Covers fw3_caps %#x (path monitoring), fw_caps %#x (syslog encryption), fw_caps %#x (SNMPv3) and fw_caps %#x (RADIUS filter).",
			FW3CapPathMonitoring, FWCapSyslogEncryption, FWCapSNMPv3, FWCapRadiusFilter), true},
		{notes + "pathmon.md", fmt.Sprintf("Claim: fw_caps %#x in both modes.", FWCapSyslogEncryption), obs.FWCaps&FWCapSyslogEncryption != 0},
		{notes + "pathmon.md", fmt.Sprintf("Claim: fw_caps %#x, takeover only.", FWCapRadiusFilter),
			DecoAgentTakeoverFWCaps&FWCapRadiusFilter != 0 && obs.FWCaps&FWCapRadiusFilter == 0 && take.FWCaps&FWCapRadiusFilter != 0},
		{notes + "snmp.md", fmt.Sprintf("**fw_caps %#x** (`supportsSNMPv3`). Claimed in **both modes** since 2026-11-19 (`models.FWCapSNMPv3`, in `DecoAgentFWCaps`): observe `fw_caps %#x`, takeover `%#x`.",
			FWCapSNMPv3, obs.FWCaps, take.FWCaps), obs.FWCaps&FWCapSNMPv3 != 0 && DecoAgentFWCaps&FWCapSNMPv3 != 0},
		{notes + "roaming-assistant.md", fmt.Sprintf("The real U6 Pro claims wifi_caps2 0x4030F0, which includes %#x.", WifiCap2RoamAssist), 0x4030F0&WifiCap2RoamAssist != 0},
		{"docs/internals.md", fmt.Sprintf("firmware features (for example `%#x` encrypted syslog; `%#x` SHA-512 SSH password;", FWCapSyslogEncryption, FWCapSHA512SSH), true},
		{"docs/internals.md", fmt.Sprintf("The UAP-AC-Pro value `%d` sets VWIRE,", inform.U7PG2.WifiCaps),
			inform.U7PG2.WifiCaps&(WifiCapBandSteer|WifiCapRFScan|WifiCapMinRateCtrl|WifiCapRadiusMACAuth|WifiCapWPA3|WifiCapWPAPSKFile|WifiCapLockAP) ==
				WifiCapBandSteer|WifiCapRFScan|WifiCapMinRateCtrl|WifiCapRadiusMACAuth|WifiCapWPA3|WifiCapWPAPSKFile|WifiCapLockAP},
		{"docs/internals.md", fmt.Sprintf("`wifi_caps2 %d` = ACS_DFS, ROAMING_ASSISTANT.", inform.U7PG2.WifiCaps2), inform.U7PG2.WifiCaps2&WifiCap2RoamAssist != 0},
		{"docs/internals.md", fmt.Sprintf("With nothing claimed (`fw_caps %d`, no `wifi_caps`)", inform.PlaceholderFWCaps), true},
	} {
		if !c.holds {
			t.Errorf("%s says %q, which the code no longer does: correct the note and this test", c.rel, c.phrase)
			continue
		}
		repotest.MustHave(t, c.rel, c.phrase)
	}
}

// docs/internals.md tells the reader how many models the catalogue has;
// the catalogue is generated (tools/gen-models.py), so the number moves
// with it.
func TestDocsCatalogueCount(t *testing.T) {
	repotest.MustHave(t, "docs/internals.md", fmt.Sprintf("`internal/models/catalog.json` lists %d UniFi AP models:", len(All())))
}
