// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/repotest"
)

// The words of the Intent are what the controller's settings are called in
// logs and notes, and they are stored: the last-good Desired on a unit's
// flash holds a security mode, a PMF word, a tx power mode and a band
// steering mode. A value changed here is a unit that no longer reads its
// own state.
func TestIntentWords(t *testing.T) {
	for got, want := range map[string]string{
		SecOpen: "open", SecWPA2: "wpa2", SecWPA3: "wpa3", SecWPA2WPA3: "wpa2wpa3",
		SecWPA2Ent: "wpa2-enterprise", SecWPA3Ent: "wpa3-enterprise", SecOWE: "owe",
		PMFDisabled: "disabled", PMFOptional: "optional", PMFRequired: "required",
		TxAuto: "auto", TxLow: "low", TxMedium: "medium", TxHigh: "high", TxCustom: "custom",
		BandSteerPrefer5G: "prefer_5g", BandSteerEqual: "equal", BandSteerOff: "off",
	} {
		if got != want {
			t.Errorf("%q, want %q", got, want)
		}
	}
	// the design doc's Intent lists the security modes
	repotest.MustContain(t, "docs/deco/agent-design.md", "Security string // "+
		strings.Join([]string{SecOpen, SecWPA2, SecWPA3, SecWPA2WPA3, SecWPA2Ent, SecWPA3Ent, SecOWE}, ", ")+"\n")
	// and the internals doc the band steering modes usteer is run for
	repotest.MustContain(t, "docs/internals.md", "usteer in local mode (`"+BandSteerPrefer5G+"`, `"+BandSteerEqual+"`)")
}

// PMFFloor per mode, the two directions of level and word, and the floor
// held by IntentFromCfg: a WLAN's PMF is never below its mode's.
func TestPMFFloor(t *testing.T) {
	for sec, want := range map[string]string{
		SecOpen: PMFDisabled, SecWPA2: PMFDisabled, SecWPA2Ent: PMFDisabled,
		SecWPA2WPA3: PMFOptional,
		SecWPA3:     PMFRequired, SecWPA3Ent: PMFRequired, SecOWE: PMFRequired,
		"": PMFDisabled, "bogus": PMFDisabled,
	} {
		if got := PMFFloor(sec); got != want {
			t.Errorf("PMFFloor(%q) = %q, want %q", sec, got, want)
		}
	}
	for level, word := range []string{PMFDisabled, PMFOptional, PMFRequired} {
		if PMFLevel(word) != level || PMFWord(level) != word {
			t.Errorf("%q: level %d, word of %d is %q", word, PMFLevel(word), level, PMFWord(level))
		}
	}
	if PMFLevel("") != -1 || PMFLevel("off") != -1 || PMFWord(-1) != "" || PMFWord(3) != "" {
		t.Error("an unknown PMF word or level is not refused")
	}
	// the controller's pmf.status and pmf.mode as a level, and as OpenWrt's
	// ieee80211w
	for _, c := range []struct {
		status, mode string
		want         int
	}{{"", "", 0}, {"disabled", "2", 0}, {"enabled", "", 1}, {"enabled", "1", 1}, {"enabled", "2", 2}, {"enabled", "3", 1}} {
		if got := pmfLevel(c.status, c.mode); got != c.want || pmf(c.status, c.mode) != string(rune('0'+c.want)) {
			t.Errorf("pmf %q/%q: level %d (%q), want %d", c.status, c.mode, got, pmf(c.status, c.mode), c.want)
		}
	}

	wlan := func(lines ...string) string {
		return "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\n" +
			"wireless.1.ssid=Home\nwireless.1.parent=wifi0\nwireless.1.devname=ath0\nwireless.1.id=w1\n" +
			"aaa.1.ssid=Home\naaa.1.devname=ath0\naaa.1.status=enabled\n" + strings.Join(lines, "\n")
	}
	modes := map[string][]string{
		SecWPA2:     {"aaa.1.wpa=2", "aaa.1.wpa.psk=good-pass-1", "aaa.1.wpa.key.1.mgmt=WPA-PSK"},
		SecWPA2WPA3: {"aaa.1.wpa=2", "aaa.1.wpa.psk=good-pass-1", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa3.transition=enabled"},
		SecWPA3:     {"aaa.1.wpa=2", "aaa.1.wpa.psk=good-pass-1", "aaa.1.wpa.key.1.mgmt=SAE"},
		SecOWE:      {"aaa.1.wpa3.support=enabled"},
		SecOpen:     {},
	}
	for sec, lines := range modes {
		for asked, pmfLines := range [][]string{{}, {"aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=1"}, {"aaa.1.pmf.status=enabled", "aaa.1.pmf.mode=2"}} {
			in, notes := IntentFromCfg(wlan(append(append([]string{}, lines...), pmfLines...)...))
			if len(in.WLANs) != 1 || in.WLANs[0].Security != sec {
				t.Fatalf("%s: fixture did not give that mode: %+v %q", sec, in.WLANs, notes)
			}
			got, floor := PMFLevel(in.WLANs[0].PMF), PMFLevel(PMFFloor(sec))
			want := max(asked, floor)
			if sec == SecOpen {
				want = 0 // no PMF without encryption, whatever was asked
			}
			if got != want {
				t.Errorf("%s asked PMF %d: %q, want level %d (floor %d)", sec, asked, in.WLANs[0].PMF, want, floor)
			}
		}
	}
}

// The controller's key management list is read in one place, with the
// caller's choice of entries: the OpenWrt path reads aaa.N.wpa.key.1 to 4,
// the intent every entry sent. They differ on an entry above 4.
func TestWPAKeyMgmtEntries(t *testing.T) {
	a := "aaa.1."
	cfg := Cfg{a + "wpa.key.1.mgmt": "WPA-PSK WPA-PSK-SHA256", a + "wpa.key.3.mgmt": "SAE", a + "wpa.key.10.mgmt": "FT-SAE", a + "wpa.key.5.mgmt": "OWE",
		"aaa.2.wpa.key.1.mgmt": "WPA-EAP"}
	if got, want := wpaKeyMgmt(cfg, a, wpaKeyFirst4), []string{"WPA-PSK", "WPA-PSK-SHA256", "SAE"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entries 1 to 4: %v, want %v", got, want)
	}
	if got, want := wpaKeySent(cfg, a), []string{"1", "3", "5", "10"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entries sent: %v, want %v", got, want)
	}
	if got, want := wpaKeyMgmt(cfg, a, wpaKeySent(cfg, a)), []string{"WPA-PSK", "WPA-PSK-SHA256", "SAE", "OWE", "FT-SAE"}; !reflect.DeepEqual(got, want) {
		t.Errorf("entries sent: %v, want %v", got, want)
	}
	if got := wpaKeyMgmt(Cfg{}, a, wpaKeyFirst4); got != nil {
		t.Errorf("nothing sent: %v", got)
	}

	// the difference, end to end: SAE only in entry 5
	only5 := Cfg{a + "wpa": "2", a + "wpa.psk": "good-pass-1", a + "wpa.key.5.mgmt": "SAE"}
	if enc, _ := encryption(only5, a); enc != "psk2+ccmp" {
		t.Errorf("OpenWrt path, SAE in entry 5: %q, want psk2+ccmp (entry 5 is not read)", enc)
	}
	var x WLANIntent
	if why := wlanSecurity(only5, "wireless.1.", a, &x, func(string, ...any) {}); why != "" || x.Security != SecWPA2 {
		// the intent sees SAE, then asks encryption() for the mode, which
		// reads entries 1 to 4: WPA2, as the OpenWrt path
		t.Errorf("intent, SAE in entry 5: %q (%s)", x.Security, why)
	}
	owe5 := Cfg{a + "wpa.key.5.mgmt": "OWE"}
	x = WLANIntent{}
	if why := wlanSecurity(owe5, "wireless.1.", a, &x, func(string, ...any) {}); why != "" || x.Security != SecOWE {
		t.Errorf("intent, OWE in entry 5: %q (%s), want owe", x.Security, why)
	}
	if enc, _ := encryption(owe5, a); enc != "none" {
		t.Errorf("OpenWrt path, OWE in entry 5: %q, want none", enc)
	}
}

// ValidWPAPassphrase is what hostapd takes as wpa_passphrase or wpa_psk.
// (bcmwifi's validPSK is this function; its test has the longer table.)
func TestValidWPAPassphrase(t *testing.T) {
	rep := strings.Repeat
	for p, want := range map[string]bool{
		"": false, rep("a", 7): false, rep("a", 8): true, rep("a", 63): true, rep("a", 65): false,
		rep("a", 64): true, rep("F", 64): true, rep("g", 64): false,
		rep("a", 7) + "\x7f": false, rep("a", 7) + "\x1f": false, rep("a", 6) + "é": false, "pass word": true,
	} {
		if got := ValidWPAPassphrase(p); got != want {
			t.Errorf("ValidWPAPassphrase(%d bytes %q) = %v, want %v", len(p), p, got, want)
		}
	}
}

// The station manager's sections (stamgr.N) have two readers with two
// rules. LegacyStamgr is the OpenWrt path's (planStamgr, and upstream uow's
// minimum RSSI kick); intentStamgr is IntentFromCfg's. They share how a
// value is read (stamgrMinRSSI, stamgrMaxSta) and nothing else. This table
// is every input they are known to differ on; which rule is right is the
// owner's to decide, and until then each reader keeps its own.
func TestStamgrReaders(t *testing.T) {
	type reading struct {
		min    int  // minimum RSSI, dBm
		minOn  bool // a minimum RSSI is in force
		maxSta int
	}
	legacy := func(cfg Cfg) reading {
		var r reading
		for _, e := range LegacyStamgr(cfg) {
			if e.Radio != "ng" {
				continue
			}
			if e.MinRSSIOn {
				r.min, r.minOn = e.MinRSSI, true
			}
			if e.MaxSta > 0 {
				r.maxSta = e.MaxSta
			}
		}
		return r
	}
	intent := func(cfg string) reading {
		in, _ := IntentFromCfg("radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\n" + cfg)
		r, ok := in.Radios["ng"]
		if !ok {
			t.Fatalf("fixture: no ng radio")
		}
		return reading{min: r.MinRSSI, minOn: r.MinRSSI != 0, maxSta: r.MaxClients} // RadioIntent.MinRSSI 0 = off
	}
	sec := func(n string, lines ...string) string {
		s := "stamgr." + n + ".radio=ng\n"
		for _, l := range lines {
			s += "stamgr." + n + "." + l + "\n"
		}
		return s
	}
	for _, c := range []struct {
		name           string
		cfg            string
		legacy, intent reading
	}{
		// read alike
		{"dBm", sec("1", "minrssi.status=true", "minrssi.rssi=-75"), reading{-75, true, 0}, reading{-75, true, 0}},
		{"above the noise floor", sec("1", "minrssi.status=true", "minrssi.rssi=20"), reading{-75, true, 0}, reading{-75, true, 0}},
		{"status false", sec("1", "minrssi.status=false", "minrssi.rssi=-75"), reading{}, reading{}},
		{"zero", sec("1", "minrssi.status=true", "minrssi.rssi=0"), reading{}, reading{}},
		{"not a number", sec("1", "minrssi.status=true", "minrssi.rssi=low"), reading{}, reading{}},
		{"no value", sec("1", "minrssi.status=true"), reading{}, reading{}},
		{"client limit", sec("2", "loadbalance.status=true", "loadbalance.maxsta=30"), reading{maxSta: 30}, reading{maxSta: 30}},
		{"client limit 0", sec("2", "loadbalance.status=true", "loadbalance.maxsta=0"), reading{}, reading{}},
		{"client limit below 0", sec("2", "loadbalance.status=true", "loadbalance.maxsta=-1"), reading{}, reading{}},
		{"client limit off", sec("2", "loadbalance.status=false", "loadbalance.maxsta=30"), reading{}, reading{}},
		{"section 8", sec("8", "minrssi.status=true", "minrssi.rssi=-70", "loadbalance.status=true", "loadbalance.maxsta=12"),
			reading{-70, true, 12}, reading{-70, true, 12}},

		// read differently
		{"status \"enabled\": only the intent takes it for true",
			sec("1", "minrssi.status=enabled", "minrssi.rssi=-75", "loadbalance.status=enabled", "loadbalance.maxsta=30"),
			reading{}, reading{-75, true, 30}},
		{"a section above 8: only the intent reads it",
			sec("9", "minrssi.status=true", "minrssi.rssi=-75", "loadbalance.status=true", "loadbalance.maxsta=30"),
			reading{}, reading{-75, true, 30}},
		{"stamgr.status=disabled: only the intent honours it",
			"stamgr.status=disabled\n" + sec("1", "minrssi.status=true", "minrssi.rssi=-75", "loadbalance.status=true", "loadbalance.maxsta=30"),
			reading{-75, true, 30}, reading{}},
		{"stamgr.N.status=disabled: only the intent honours it",
			sec("1", "status=disabled", "minrssi.status=true", "minrssi.rssi=-75", "loadbalance.status=true", "loadbalance.maxsta=30"),
			reading{-75, true, 30}, reading{}},
		{"95 above the noise floor (0 dBm): a threshold for the OpenWrt path, off for the intent",
			sec("1", "minrssi.status=true", "minrssi.rssi=95"), reading{0, true, 0}, reading{}},
	} {
		if got := legacy(ParseCfg(c.cfg)); got != c.legacy {
			t.Errorf("%s: LegacyStamgr %+v, want %+v", c.name, got, c.legacy)
		}
		if got := intent(c.cfg); got != c.intent {
			t.Errorf("%s: IntentFromCfg %+v, want %+v", c.name, got, c.intent)
		}
	}

	// what LegacyStamgr hands back: the sections that say anything, by
	// number, a section without a radio included (its meaning is the
	// caller's: planStamgr passes it over, upstream's uow keeps it under "")
	got := LegacyStamgr(ParseCfg("stamgr.3.minrssi.status=true\nstamgr.3.minrssi.rssi=-70\n" +
		"stamgr.1.radio=6e\nstamgr.2.minrssi.rssi=-60\nstamgr.2.loadbalance.maxsta=9\nstamgr.4.radio=na\nstamgr.4.loadbalance.status=true\nstamgr.4.loadbalance.maxsta=40"))
	want := []StamgrEntry{{N: 1, Radio: "6e"}, {N: 3, MinRSSI: -70, MinRSSIOn: true}, {N: 4, Radio: "na", MaxSta: 40}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("LegacyStamgr = %+v, want %+v", got, want)
	}

	// and the plan writes the 0 dBm threshold (the edge above)
	cur := UCI{"wireless.radio0": "wifi-device", "wireless.radio0.band": "2g"}
	var r Result
	ops := planStamgr(ParseCfg(sec("1", "minrssi.status=true", "minrssi.rssi=95")), cur, &r)
	if len(ops) != 1 || ops[0].Key != "wireless.radio0.rssi_reject_assoc_rssi" || ops[0].Value != "0" || ops[0].Del {
		t.Errorf("plan for 95 above the noise floor: %+v", ops)
	}
}

// The login name rule is handed out for the test that holds it to
// internal/device's (cmd/udeco-ap): the pattern users are checked with,
// and a copy of the system accounts.
func TestLoginNameAccessors(t *testing.T) {
	if LoginNamePattern() != userName.String() {
		t.Errorf("pattern %q", LoginNamePattern())
	}
	names := SystemUsers()
	if len(names) != len(systemUsers) {
		t.Fatalf("SystemUsers: %v", names)
	}
	for i, n := range names {
		if !systemUsers[n] || i > 0 && names[i-1] >= n {
			t.Errorf("SystemUsers: %q (sorted, and a system account)", n)
		}
	}
}
