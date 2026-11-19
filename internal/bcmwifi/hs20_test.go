// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/hs20"
)

func testHotspot2() *Hotspot2 {
	return &Hotspot2{
		AccessNetworkType: 2, Internet: true, Venue: &hs20.VenueInfo{Group: 2, Type: 8},
		VenueNames:  []hs20.VenueName{{Lang: "eng", Name: "Cafe"}},
		DisableDGAF: true, ANQPDomainID: -1, IPAddrAvail: 0x0e,
		NAIRealms:        []hs20.NAIRealm{{Realm: "example.com", EAP: []hs20.EAPMethod{{Method: 21, Auth: []hs20.AuthParam{{ID: 2, Val: 4}}}}}},
		RoamingConsortia: []string{"506f9a"},
	}
}

func hs20SSID() SSID {
	return SSID{ID: "hs", SSID: "Passpoint", Bands: []string{"na"}, Enabled: true, Security: SecWPA2Ent,
		Radius:   &Radius{Auth: []RadiusServer{{IP: "192.168.0.10", Secret: testSecret}}},
		Hotspot2: testHotspot2()}
}

func TestNormalizeHotspot2(t *testing.T) {
	in := hs20SSID()
	s, notes, ok := normalizeSSID(in)
	if !ok {
		t.Fatalf("skipped: %q", notes)
	}
	if s.PMF != "optional" || !strings.Contains(strings.Join(notes, "\n"), "PMF raised to optional") {
		t.Errorf("PMF %q notes %q", s.PMF, notes)
	}
	if !strings.Contains(strings.Join(notes, "\n"), "DGAF disabled") {
		t.Errorf("no DGAF note: %q", notes)
	}
	if s.Hotspot2 == in.Hotspot2 {
		t.Error("normalized SSID shares the caller's Hotspot2")
	}
	// with isolation and proxy ARP the DGAF note goes away; PMF required stays
	in.Isolation, in.ProxyARP, in.PMF = true, true, "required"
	s, notes, _ = normalizeSSID(in)
	if s.PMF != "required" || strings.Contains(strings.Join(notes, "\n"), "DGAF") {
		t.Errorf("PMF %q notes %q", s.PMF, notes)
	}
}

// hostapd refuses hs20=1 without WPA2-Enterprise/CCMP ("HS 2.0:
// WPA2-Enterprise/CCMP configuration is required"), and with it every SSID
// of the radio: such an SSID is never served.
func TestHotspot2NeedsEnterprise(t *testing.T) {
	for _, sec := range []string{SecOpen, SecWPA2, SecWPA3, SecWPA2WPA3} {
		s := hs20SSID()
		s.Security, s.Passphrase, s.Radius = sec, testPSK, nil
		if _, notes, ok := normalizeSSID(s); ok || !strings.Contains(strings.Join(notes, "\n"), "needs WPA2/WPA3-Enterprise") {
			t.Errorf("%s: ok=%t notes %q", sec, ok, notes)
		}
	}
	s := hs20SSID()
	s.Hotspot2.RoamingConsortia = []string{"00"} // not something Parse keeps
	if _, notes, ok := normalizeSSID(s); ok || !strings.Contains(strings.Join(notes, "\n"), "roaming_consortium") {
		t.Errorf("bad config served: %q", notes)
	}
	if err := writeHotspot2(func(string, any) {}, SSID{Security: SecWPA2, Hotspot2: testHotspot2()}); err == nil {
		t.Error("writeHotspot2 wrote Hotspot 2.0 on a PSK SSID")
	}
}

// The rendered radio conf carries the hs20 lines inside the SSID's bss=
// section, as bare key=value lines, next to WPA2-Enterprise with PMF.
func TestRenderHotspot2(t *testing.T) {
	s, _, ok := normalizeSSID(hs20SSID())
	if !ok {
		t.Fatal("skipped")
	}
	plain, _, _ := normalizeSSID(SSID{ID: "p", SSID: "Home", Bands: []string{"na"}, Enabled: true, Security: SecWPA2, Passphrase: testPSK})
	hr := hapdRadio{Band: "na", Channel: 36, MaxSta: 32, RunDir: DefaultRunDir,
		Placeholder: hapdPlaceholder{Vif: "wl11", SSID: "udeco-0123456789ab", Passphrase: testPlaceholderPSK},
		BSS: []hapdBSS{
			{Vif: "wl12", BSSID: "be:a7:b9:3e:17:05", Bridge: "br-lan", SSID: plain},
			{Vif: "wl13", BSSID: "be:a7:b9:3e:17:06", Bridge: "br-lan", SSID: s},
		}}
	conf, err := renderHostapd(hr)
	if err != nil {
		t.Fatal(err)
	}
	line := regexp.MustCompile(`^[a-z0-9_]+=[^\n]*$`)
	sections := strings.Split(conf, "\nbss=")
	if len(sections) != 3 {
		t.Fatalf("%d sections", len(sections))
	}
	for _, l := range strings.Split(strings.TrimSuffix(conf, "\n"), "\n") {
		if !line.MatchString(l) {
			t.Errorf("line %q", l)
		}
		k, v, _ := strings.Cut(l, "=")
		if isHS20Key(k) {
			if err := hs20.CheckLine(k, v); err != nil {
				t.Error(err)
			}
		}
	}
	for _, k := range []string{"interworking", "hs20", "venue_name", "nai_realm", "roaming_consortium"} {
		if strings.Contains(sections[0], "\n"+k+"=") || strings.Contains(sections[1], "\n"+k+"=") {
			t.Errorf("%s outside the Hotspot 2.0 BSS", k)
		}
	}
	h := sections[2]
	for _, want := range []string{"\ninterworking=1\n", "\nhs20=1\n", "\ndisable_dgaf=1\n", "\nwpa_key_mgmt=WPA-EAP\n", "\nieee80211w=1\n",
		"\nrsn_pairwise=CCMP\n", "\nieee8021x=1\n", "\nnai_realm=0,example.com,21[2:4]\n", "\nipaddr_type_availability=0e\n"} {
		if !strings.Contains(h, want) {
			t.Errorf("Hotspot 2.0 BSS lacks %q:\n%s", strings.TrimSpace(want), h)
		}
	}
}

func isHS20Key(k string) bool {
	for _, x := range hs20.Keys {
		if x == k {
			return true
		}
	}
	return false
}

// The Hotspot2 pointer survives the JSON clone and secret split that
// last-good storage uses, and an SSID without it marshals as before.
func TestHotspot2Persists(t *testing.T) {
	d := Desired{SSIDs: []SSID{hs20SSID(), {ID: "p", SSID: "Home", Security: SecWPA2, Passphrase: testPSK}}}
	pub, _ := splitSecrets(d)
	if pub.SSIDs[0].Hotspot2 == nil || len(pub.SSIDs[0].Hotspot2.NAIRealms) != 1 || pub.SSIDs[1].Hotspot2 != nil {
		t.Fatalf("clone lost Hotspot2: %+v", pub.SSIDs)
	}
	if b, _ := json.Marshal(d.SSIDs[1]); strings.Contains(string(b), "Hotspot2") {
		t.Errorf("an SSID without Hotspot 2.0 marshals the field: %s", b)
	}
}
