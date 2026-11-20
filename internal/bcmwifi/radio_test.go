// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestChanspecRoundTrip(t *testing.T) {
	for _, c := range []struct {
		in   string
		ctrl int
		w    int
	}{
		{"44/80 (0xe22a)", 44, 80}, {"2l (0x1804)", 2, 40}, {"7u (0x1905)", 7, 40},
		{"6 (0x1006)", 6, 20}, {"36", 36, 20}, {"149l", 149, 40}, {"153u", 153, 40},
	} {
		cs, err := parseChanspec(c.in)
		if err != nil || cs.Ctrl != c.ctrl || cs.Width != c.w {
			t.Errorf("parse %q = %+v %v", c.in, cs, err)
			continue
		}
		if got := cs.String(); got != strings.Fields(c.in)[0] {
			t.Errorf("String(%+v) = %q, want %q", cs, got, strings.Fields(c.in)[0])
		}
	}
	// Live fixtures parse.
	for _, f := range []string{"wl_-i_wl0_chanspec.txt", "wl_-i_wl1_chanspec.txt"} {
		b, _ := os.ReadFile(filepath.Join(fixtures, f))
		if _, err := parseChanspec(string(b)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
}

func TestDesiredChanspec(t *testing.T) {
	live5 := chanspec{44, 80}
	live2 := chanspec{2, 40}
	for _, c := range []struct {
		band   string
		r      Radio
		live   chanspec
		want   string
		change bool
	}{
		{"na", Radio{Channel: 36, Width: 80}, live5, "36/80", true},
		{"na", Radio{Channel: 44, Width: 80}, live5, "44/80", false},
		{"na", Radio{Channel: 40, Width: 40}, live5, "40u", true},
		{"na", Radio{Channel: 157, Width: 160}, live5, "157/80", true},
		{"na", Radio{Channel: 165, Width: 80}, live5, "165", true},
		{"na", Radio{Channel: 0, Width: 0}, live5, "44/80", false},
		{"na", Radio{Channel: 0, Width: 20}, live5, "44", true},
		{"na", Radio{Channel: 50, Width: 20}, live5, "44/80", false},
		{"ng", Radio{Channel: 6, Width: 20}, live2, "6", true},
		{"ng", Radio{Channel: 11, Width: 40}, live2, "11u", true},
		{"ng", Radio{Channel: 3, Width: 80}, live2, "3l", true},
		{"ng", Radio{Channel: 0, Width: 40}, live2, "2l", false},
	} {
		cs, ch, _ := desiredChanspec(c.band, c.r, c.live, nil)
		if cs.String() != c.want || ch != c.change {
			t.Errorf("%s %+v from %s: got %s/%t, want %s/%t", c.band, c.r, c.live, cs, ch, c.want, c.change)
		}
	}
}

func TestTxpwrDegrade(t *testing.T) {
	// U6 Pro presets over the radio's ceiling (the target maximum at no
	// degrade): low = the floor (5 dBm), medium = halfway between floor and
	// ceiling, high and auto = the ceiling, custom clamped to [floor, ceiling].
	for _, c := range []struct {
		r    Radio
		max  float64
		want int
		mode string
		dbm  int
		note bool
	}{
		{Radio{TxPowerMode: "auto"}, 23.5, 0, "auto", 24, false},
		{Radio{TxPowerMode: "high"}, 23.5, 0, "high", 24, false},
		{Radio{TxPowerMode: "medium"}, 23.5, 37, "medium", 14, false}, // 14.25 dBm
		{Radio{TxPowerMode: "low"}, 23.5, 74, "low", 5, false},
		{Radio{TxPowerMode: "custom", TxPower: 20}, 24, 16, "custom", 20, false},
		{Radio{TxPowerMode: "custom", TxPower: 30}, 24, 0, "custom", 24, true},
		{Radio{TxPowerMode: "custom", TxPower: 1}, 23.5, 74, "custom", 5, true},
		{Radio{TxPowerMode: "medium"}, 0, 12, "medium", 0, true}, // ceiling unknown: the old fixed steps
		{Radio{TxPowerMode: "low"}, 0, 24, "low", 0, true},
		{Radio{TxPowerMode: "bogus"}, 24, 0, "high", 24, true},
	} {
		got, n := txpwrDegrade(c.r, c.max)
		if got != c.want || (n != "") != c.note {
			t.Errorf("%+v max %.2f: got %d %q, want %d", c.r, c.max, got, n, c.want)
		}
		if m, d := txReportFor(c.r, c.max, got); m != c.mode || d != c.dbm {
			t.Errorf("%+v max %.2f: report %s %d, want %s %d", c.r, c.max, m, d, c.mode, c.dbm)
		}
	}
	b, _ := os.ReadFile(filepath.Join(fixtures, "wl_-i_wl1_txpwr_target_max.txt"))
	if got := parseTargetMax(string(b)); got != 23.5 {
		t.Errorf("target max %v", got)
	}
}

func TestCountry(t *testing.T) {
	c := parseCountry("US (US/0) UNITED STATES")
	if c.Code != "US" || c.Rev != 0 {
		t.Fatalf("%+v", c)
	}
	if arg, same := countryArg("us", c); arg != "US/0" || !same {
		t.Errorf("US: %q %t", arg, same)
	}
	if arg, same := countryArg("CA", c); arg != "CA/2" || same {
		t.Errorf("CA: %q %t", arg, same)
	}
	if arg, same := countryArg("IN", c); arg != "IN/288" || same {
		t.Errorf("IN: %q %t", arg, same)
	}
}

func TestSSIDMatches(t *testing.T) {
	for _, c := range []struct {
		out, want string
		ok        bool
	}{
		{`Current SSID: "Example Network"`, "Example Network", true},
		{`Current SSID: "olive#"`, "olive#", true},
		{`Current SSID: "a\\b"`, `a\b`, true},
		{`Current SSID: "caf\xC3\xA9"`, "café", true},
		{`Current SSID: "caf\xc3\xa9"`, "café", true},
		{`Current SSID: "Other"`, "Example Network", false},
		{`Current SSID: ""`, "x", false},
	} {
		if got := ssidMatches(c.out, c.want); got != c.ok {
			t.Errorf("ssidMatches(%q, %q) = %t", c.out, c.want, got)
		}
	}
}

func TestSecretsNeverPrinted(t *testing.T) {
	d := twoSSIDs()
	d.SSIDs = append(d.SSIDs, SSID{ID: "e", SSID: "Corp", Enabled: true, Security: SecWPA2Ent,
		Radius: &Radius{Auth: []RadiusServer{{IP: "10.0.0.1", Secret: testSecret}}}})
	for _, verb := range []string{"%v", "%+v", "%#v", "%s"} {
		s := fmt.Sprintf(verb, d)
		if strings.Contains(s, testPSK) || strings.Contains(s, testSecret) || strings.Contains(s, "iot-passphrase-1") {
			t.Errorf("%s leaks a secret: %s", verb, s)
		}
	}
	pub, sec := splitSecrets(d)
	if strings.Contains(fmt.Sprint(pub.SSIDs[2].Radius.Auth[0].Secret), testSecret) || pub.SSIDs[1].Passphrase != "" {
		t.Error("public copy keeps secrets")
	}
	if d.SSIDs[1].Passphrase != testPSK || d.SSIDs[2].Radius.Auth[0].Secret != testSecret {
		t.Error("splitSecrets modified its input")
	}
	joinSecrets(&pub, sec)
	if !sameDesired(pub, d) {
		t.Error("split+join does not round-trip")
	}
}

func TestNormalizeSSID(t *testing.T) {
	for _, c := range []struct {
		s    SSID
		ok   bool
		note string
	}{
		{SSID{ID: "1", SSID: "x", Security: SecWPA2, Passphrase: "short"}, false, "passphrase"},
		{SSID{ID: "2", SSID: "x", Security: SecWPA3, Passphrase: strings.Repeat("a", 64)}, false, "SAE"},
		{SSID{ID: "3", SSID: strings.Repeat("s", 33), Security: SecOpen}, false, "length"},
		{SSID{ID: "4", SSID: "a\nb", Security: SecOpen}, false, "control"},
		{SSID{ID: "5", SSID: "x", Security: SecWPA2Ent}, false, "radius"},
		{SSID{ID: "6", SSID: "x", Security: "wep"}, false, "not supported"},
		{SSID{ID: "7", SSID: "x", Security: SecOpen, VLAN: 5000}, false, "VLAN"},
		// the minimum-rate note depends on Options.MinRates: planLayout writes it
		{SSID{ID: "8", SSID: "x", Security: "", MinRateKbps: map[string]int{"ng": 6000}}, true, ""},
		{SSID{ID: "9", SSID: "x", Security: SecWPA2, Passphrase: "abcdefgh", MACFilter: &MACFilter{Policy: "block"}}, false, "MAC filter"},
		// RADIUS MAC authentication without a usable server: not served
		// (an open SSID would otherwise come up open to everyone)
		{SSID{ID: "10", SSID: "x", Security: SecOpen, Radius: &Radius{MACAuth: true}}, false, "RADIUS MAC authentication"},
		{SSID{ID: "11", SSID: "x", Security: SecOpen, Radius: &Radius{MACAuth: true, Auth: []RadiusServer{{IP: "10.0.0.1"}}}}, false, "RADIUS MAC authentication"},
		{SSID{ID: "12", SSID: "x", Security: SecWPA2, Passphrase: "abcdefgh", Radius: &Radius{MACAuth: true, Auth: []RadiusServer{{IP: "bad", Secret: "s3"}}}}, false, "RADIUS MAC authentication"},
		{SSID{ID: "13", SSID: "x", Security: SecOpen, Radius: &Radius{MACAuth: true, Auth: []RadiusServer{{IP: "10.0.0.1", Secret: "s3"}}}}, true, ""},
		// Radius without MACAuth on a personal SSID stays ignored, as before
		{SSID{ID: "14", SSID: "x", Security: SecOpen, Radius: &Radius{}}, true, ""},
	} {
		got, notes, ok := normalizeSSID(c.s)
		n := strings.Join(notes, "\n")
		if ok != c.ok || !strings.Contains(n, c.note) {
			t.Errorf("%s: ok=%t notes=%q", c.s.ID, ok, n)
		}
		if strings.Contains(n, c.s.Passphrase) && c.s.Passphrase != "" {
			t.Errorf("%s: note leaks the passphrase", c.s.ID)
		}
		if ok && got.Security == "" {
			t.Errorf("%s: security not defaulted", c.s.ID)
		}
	}
}

func TestParseMaclist(t *testing.T) {
	got := parseMaclist("mac 1C:53:F9:79:81:35 2\nmac FC:3C:D7:5E:F1:F8 2\n")
	if len(got) != 2 || got[0] != "1c:53:f9:79:81:35" {
		t.Errorf("%v", got)
	}
}
