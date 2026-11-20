// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite golden files")

// Test passphrases and secrets: fake values, never real ones.
const (
	testPSK            = "correct horse battery"
	testSecret         = "radius-test-secret"
	testPlaceholderPSK = "placeholder-test-passphrase"
)

func goldenCases() map[string]struct {
	band   string
	radio  Radio
	ssids  []SSID
	block  []string
	notes  []string // substrings expected in layout notes
	absent []string // substrings that must not be in the conf
} {
	wpa2 := SSID{ID: "a1", SSID: "Home", Bands: []string{"na"}, Enabled: true, Security: SecWPA2, Passphrase: testPSK}
	return map[string]struct {
		band   string
		radio  Radio
		ssids  []SSID
		block  []string
		notes  []string
		absent []string
	}{
		"open_ng": {band: "ng", radio: Radio{Enabled: true, Channel: 6},
			ssids: []SSID{{ID: "o", SSID: "Guest WiFi #2", Bands: []string{"2g"}, Enabled: true, Security: "open"}}},
		"wpa2_ft_hidden_isolated": {band: "na", radio: Radio{Enabled: true, Channel: 36, MinRSSI: -75, MaxClients: 40},
			ssids: []SSID{func() SSID {
				s := wpa2
				s.FT, s.Hidden, s.Isolation, s.GroupRekey = true, true, true, 3600
				s.DTIM = map[string]int{"na": 3}
				return s
			}()}},
		"wpa2_pmf_required_hexpsk": {band: "na", radio: Radio{Enabled: true},
			ssids: []SSID{func() SSID {
				s := wpa2
				s.PMF = "required"
				s.Passphrase = strings.Repeat("ab", 32)
				return s
			}()}},
		"wpa3_ft_dropped": {band: "na", radio: Radio{Enabled: true},
			ssids: []SSID{{ID: "w3", SSID: "Sae Only", Bands: []string{"na"}, Enabled: true, Security: SecWPA3, Passphrase: testPSK, FT: true}},
			notes: []string{"FT-SAE needs"}, absent: []string{"FT-", "mobility_domain"}},
		"transition_ft_psk_only": {band: "na", radio: Radio{Enabled: true},
			ssids:  []SSID{{ID: "t", SSID: "Example Network", Bands: []string{"na"}, Enabled: true, Security: SecWPA2WPA3, Passphrase: testPSK, FT: true, BSSTransition: true, RRM: true}},
			absent: []string{"FT-SAE", "rrm_"}},
		"wpa2_enterprise": {band: "na", radio: Radio{Enabled: true},
			ssids: []SSID{{ID: "e", SSID: "Corp", Bands: []string{"na"}, Enabled: true, Security: SecWPA2Ent, FT: true,
				Radius: &Radius{Auth: []RadiusServer{{IP: "192.168.0.10", Secret: testSecret}}, Acct: []RadiusServer{{IP: "192.168.0.10", Port: 1913, Secret: testSecret}}, OwnIP: "192.168.0.205", InterimSeconds: 600}}},
			notes: []string{"FT-EAP needs"}, absent: []string{"mobility_domain"}},
		"wpa3_enterprise": {band: "na", radio: Radio{Enabled: true},
			ssids: []SSID{{ID: "e3", SSID: "Corp3", Bands: []string{"na"}, Enabled: true, Security: SecWPA3Ent,
				Radius: &Radius{Auth: []RadiusServer{{IP: "10.0.0.2", Port: 1812, Secret: testSecret}}, NASID: "deco-office"}}}},
		// RADIUS MAC authentication on an open SSID: macaddr_acl=2 with the
		// RADIUS servers, never an open BSS without the check.
		"open_radius_macauth": {band: "ng", radio: Radio{Enabled: true, Channel: 6},
			ssids: []SSID{{ID: "m", SSID: "Lobby", Bands: []string{"ng"}, Enabled: true, Security: SecOpen,
				Radius: &Radius{Auth: []RadiusServer{{IP: "192.168.0.10", Secret: testSecret}}, MACAuth: true, MACFormat: "xx-xx-xx-xx-xx-xx"}}},
			notes: []string{"MAC format"}, absent: []string{"macaddr_acl=0", "accept_mac_file", "ieee8021x"}},
		// MAC auth plus an allow list: the driver enforces the list (wl
		// macmode 2), hostapd asks RADIUS about everyone (no accept file,
		// whose entries would skip RADIUS).
		"wpa2_ft_macauth_allow": {band: "na", radio: Radio{Enabled: true},
			ssids: []SSID{func() SSID {
				s := wpa2
				s.FT = true
				s.MACFilter = &MACFilter{Policy: "allow", MACs: []string{"aa:bb:cc:00:00:01"}}
				s.Radius = &Radius{Auth: []RadiusServer{{IP: "10.0.0.2", Port: 1812, Secret: testSecret}}, MACAuth: true}
				return s
			}()},
			absent: []string{"macaddr_acl=1", "accept_mac_file"}},
		"macfilter_allow_with_block": {band: "na", radio: Radio{Enabled: true},
			ssids: []SSID{func() SSID {
				s := wpa2
				s.MACFilter = &MACFilter{Policy: "Allow", MACs: []string{"AA:BB:CC:00:00:01", "aa-bb-cc-00-00-02", "bogus"}}
				return s
			}()},
			block: []string{"aa:bb:cc:00:00:02"}, notes: []string{"1 invalid MAC"}},
		"multi_vlan_features": {band: "na", radio: Radio{Enabled: true, Channel: 149, Width: 80},
			ssids: []SSID{
				func() SSID { s := wpa2; s.ID = "b"; s.UAPSD, s.MulticastToUnicast = true, true; return s }(),
				{ID: "c", SSID: "IoT", Bands: []string{"na", "ng"}, Enabled: true, Security: SecWPA2, Passphrase: testPSK, VLAN: 20, Isolation: true, ProxyARP: true,
					MACFilter: &MACFilter{Policy: "deny", MACs: []string{"11:22:33:44:55:66"}}},
				{ID: "d", SSID: "NoProxy", Bands: []string{"na"}, Enabled: true, Security: SecOpen, ProxyARP: true},
			},
			// proxy_arp fails hostapd on a vif it creates (F5): never written.
			block: []string{"de:ad:be:ef:00:01"}, absent: []string{"proxy_arp"}},
	}
}

// renderCase places the SSIDs with planLayout on the fixture vif set and
// renders the radio's conf with fixed MACs.
func renderCase(t *testing.T, band string, r Radio, ssids []SSID, block []string) (string, *layout) {
	t.Helper()
	exists := func(n string) bool {
		return regexp.MustCompile(`^wl[01][1-6]?$`).MatchString(n)
	}
	// Placement rules (R23) are tested in plan_test.go; here any vif may
	// carry a br-lan SSID so the goldens cover several BSSes per conf.
	l := planLayout(Desired{Country: "US", Radios: map[string]Radio{band: r}, SSIDs: ssids}, exists, layoutOpts{anyVifOnLAN: true, guestOK: true})
	rl := l.radio(band)
	hr := hapdRadio{Band: band, Channel: r.Channel, Country: "US", MinRSSI: r.MinRSSI, MaxSta: defaultMaxSta, RunDir: DefaultRunDir,
		Placeholder: hapdPlaceholder{Vif: bandPrimary[band] + "1", SSID: "udeco-0123456789ab", Passphrase: testPlaceholderPSK}}
	if r.MaxClients > 0 {
		hr.MaxSta = r.MaxClients
	}
	for i, u := range rl.Used {
		mac := "be:a7:b9:3e:17:0" + string(rune('5'+i))
		d := driverFor(u, mac, hr.MaxSta, block, false)
		hr.BSS = append(hr.BSS, hapdBSS{Vif: u.Vif, BSSID: mac, Bridge: u.Bridge, SSID: u.SSID, Accept: d.Allow})
	}
	conf, err := renderHostapd(hr)
	if err != nil {
		t.Fatal(err)
	}
	return conf, l
}

var confLine = regexp.MustCompile(`^[a-z0-9_]+=[^\n]*$`)

func TestHostapdGolden(t *testing.T) {
	for name, c := range goldenCases() {
		t.Run(name, func(t *testing.T) {
			conf, l := renderCase(t, c.band, c.radio, c.ssids, c.block)
			for i, line := range strings.Split(strings.TrimSuffix(conf, "\n"), "\n") {
				if !confLine.MatchString(line) {
					t.Errorf("line %d %q is not a bare key=value", i+1, line)
				}
				if err := checkHostapdValue(line); err != nil {
					t.Errorf("line %d: %v", i+1, err)
				}
			}
			for _, a := range c.absent {
				if strings.Contains(conf, a) {
					t.Errorf("conf contains %q", a)
				}
			}
			notes := strings.Join(l.Notes, "\n")
			for _, n := range c.notes {
				if !strings.Contains(notes, n) {
					t.Errorf("notes %q lack %q", notes, n)
				}
			}
			gold := filepath.Join("testdata", "golden", name+".conf")
			if *update {
				if err := os.MkdirAll(filepath.Dir(gold), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(gold, []byte(conf), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(gold)
			if err != nil {
				t.Fatalf("%v (run go test -update)", err)
			}
			if conf != string(want) {
				t.Errorf("conf differs from %s:\n--- got\n%s\n--- want\n%s", gold, conf, want)
			}
		})
	}
}

// checkHostapdValue applies hostapd 2.9 config_file.c's format checks for
// the keys whose values it parses strictly; a failure there aborts the
// whole hostapd ("Line %d: Invalid r1_key_holder '%s'" etc.).
func checkHostapdValue(line string) error {
	k, v, _ := strings.Cut(line, "=")
	hex := regexp.MustCompile(`^[0-9a-fA-F]*$`)
	switch k {
	case "r1_key_holder":
		if len(v) != 12 || !hex.MatchString(v) {
			return fmt.Errorf("r1_key_holder %q: hostapd wants 12 hex digits, no colons", v)
		}
	case "mobility_domain":
		if len(v) != 4 || !hex.MatchString(v) {
			return fmt.Errorf("mobility_domain %q: hostapd wants 4 hex digits", v)
		}
	case "nas_identifier":
		if len(v) < 1 || len(v) > 48 {
			return fmt.Errorf("nas_identifier %q: must be 1..48 octets", v)
		}
	case "bssid":
		if _, err := net.ParseMAC(v); err != nil || len(v) != 17 {
			return fmt.Errorf("bssid %q: %v", v, err)
		}
	}
	return nil
}

func TestKeyMgmt(t *testing.T) {
	for _, c := range []struct {
		s    SSID
		mgmt string
		pmf  int
	}{
		{SSID{Security: SecWPA2}, "WPA-PSK", 0},
		{SSID{Security: SecWPA2, PMF: "optional", FT: true}, "WPA-PSK FT-PSK", 1},
		{SSID{Security: SecWPA2, PMF: "required"}, "WPA-PSK WPA-PSK-SHA256", 2},
		{SSID{Security: SecWPA3, PMF: "disabled"}, "SAE", 2},
		{SSID{Security: SecWPA2WPA3, PMF: "disabled"}, "WPA-PSK SAE", 1},
		{SSID{Security: SecWPA2WPA3, PMF: "required", FT: true}, "WPA-PSK FT-PSK SAE", 2},
		{SSID{Security: SecWPA2Ent, PMF: "required"}, "WPA-EAP WPA-EAP-SHA256", 2},
		{SSID{Security: SecWPA3Ent}, "WPA-EAP WPA-EAP-SHA256", 2},
	} {
		m, p := keyMgmt(c.s)
		if m != c.mgmt || p != c.pmf {
			t.Errorf("%s pmf=%q ft=%t: got %q/%d, want %q/%d", c.s.Security, c.s.PMF, c.s.FT, m, p, c.mgmt, c.pmf)
		}
	}
}

func TestMobilityDomainStable(t *testing.T) {
	a, b := mobilityDomain("Home"), mobilityDomain("Home")
	if a != b || a == 0 || a == mobilityDomain("Home2") {
		t.Fatalf("mdid %04x %04x", a, b)
	}
}
