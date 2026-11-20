// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/repotest"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// Tests that hold bcmwifi to the Intent vocabulary and rules of
// internal/translate, which produces what bcmwifi is given.

// validPSK is translate's passphrase rule (with hexOK), and without hexOK
// the same rule less the 64 hex digits. The wanted answers are what validPSK
// gave while it was its own code.
func TestValidPSKIsTranslatesRule(t *testing.T) {
	rep := strings.Repeat
	for _, c := range []struct {
		p          string
		hex, noHex bool // validPSK(p, true), validPSK(p, false)
		name       string
	}{
		{p: "", name: "empty"},
		{p: rep("a", 7), name: "7 characters"},
		{p: rep("a", 8), hex: true, noHex: true, name: "8 characters"},
		{p: "pass word", hex: true, noHex: true, name: "a space"},
		{p: rep("a", 7) + "~", hex: true, noHex: true, name: "0x7e, the last printable"},
		{p: rep("a", 63), hex: true, noHex: true, name: "63 characters"},
		{p: rep("a", 64), hex: true, name: "64 hex digits (lower case)"},
		{p: rep("A", 64), hex: true, name: "64 hex digits (upper case)"},
		{p: rep("0", 64), hex: true, name: "64 hex digits (digits)"},
		{p: rep("f", 63) + "g", name: "64 characters, one not hex"},
		{p: rep("g", 64), name: "64 characters, none hex"},
		{p: rep("a", 65), name: "65 characters"},
		{p: rep("a", 7) + "\x7f", name: "DEL"},
		{p: rep("a", 7) + "\x1f", name: "a control character"},
		{p: rep("a", 6) + "é", name: "non-ASCII, 8 bytes"},
		{p: rep("é", 4), name: "non-ASCII only, 8 bytes"},
		{p: rep("a", 62) + "é", name: "non-ASCII, 64 bytes"},
		{p: rep("é", 32), name: "non-ASCII only, 64 bytes"},
		{p: rep("a", 7) + "\xff", name: "not UTF-8, 8 bytes"},
		{p: rep("0", 63) + "\xff", name: "not UTF-8, 64 bytes"},
	} {
		if got := validPSK(c.p, true); got != c.hex {
			t.Errorf("%s: validPSK(hex ok) = %v, want %v", c.name, got, c.hex)
		}
		if got := validPSK(c.p, false); got != c.noHex {
			t.Errorf("%s: validPSK(no hex) = %v, want %v", c.name, got, c.noHex)
		}
		if got := translate.ValidWPAPassphrase(c.p); got != c.hex {
			t.Errorf("%s: translate.ValidWPAPassphrase = %v, want %v", c.name, got, c.hex)
		}
	}
}

// Every per-band setting (the fields of BandSettings, translate's BandWLAN)
// is applied by ForBand and read back by bandSettings: both name the fields
// one by one.
func TestBandSettingsFieldsCarried(t *testing.T) {
	var b BandSettings
	v := reflect.ValueOf(&b).Elem()
	st := reflect.TypeOf(SSID{})
	for i := 0; i < v.NumField(); i++ {
		name := v.Type().Field(i).Name
		if f, ok := st.FieldByName(name); !ok || f.Type != v.Field(i).Type() {
			t.Errorf("BandSettings.%s: SSID has no field of that name and type", name)
		}
		switch f := v.Field(i); f.Kind() {
		case reflect.String:
			f.SetString("x")
		case reflect.Bool:
			f.SetBool(true)
		case reflect.Int:
			f.SetInt(7)
		default:
			t.Fatalf("BandSettings.%s: no test value for a %s", name, f.Kind())
		}
	}
	for _, band := range []string{"ng", "5g"} { // by its name, and by the other name of the band
		key := map[string]string{"ng": "ng", "5g": "na"}[band]
		s := SSID{ID: "w", PerBand: map[string]BandSettings{key: b}}.ForBand(band)
		got := reflect.ValueOf(s)
		for i := 0; i < v.NumField(); i++ {
			name := v.Type().Field(i).Name
			if !reflect.DeepEqual(got.FieldByName(name).Interface(), v.Field(i).Interface()) {
				t.Errorf("ForBand(%s) does not set %s", band, name)
			}
		}
		if back := s.bandSettings(); back != b {
			t.Errorf("bandSettings after ForBand(%s): %+v, want %+v", band, back, b)
		}
	}
	// a band without settings of its own keeps the SSID's
	if s := (SSID{Security: SecWPA2, PerBand: map[string]BandSettings{"na": b}}).ForBand("ng"); s.Security != SecWPA2 {
		t.Errorf("ForBand(ng) took another band's settings: %s", s.Security)
	}
}

// The two per-band types are translate's since they were one list; the
// last-good Desired on flash holds them, so their JSON is what bcmwifi's own
// types wrote (the strings below are those types' output).
func TestPerBandTypesOnFlash(t *testing.T) {
	b, err := json.Marshal(BandSettings{Security: "s", PMF: "p", FT: true, FTSAE: true, FTOverDS: true, MobilityDomain: "m",
		BSSTransition: true, RRM: true, UAPSD: true, ProxyARP: true, MulticastToUnicast: true, Hidden: true, Isolation: true, GroupRekey: 7})
	if want := `{"Security":"s","PMF":"p","FT":true,"FTSAE":true,"FTOverDS":true,"MobilityDomain":"m","BSSTransition":true,"RRM":true,` +
		`"UAPSD":true,"ProxyARP":true,"MulticastToUnicast":true,"Hidden":true,"Isolation":true,"GroupRekey":7}`; err != nil || string(b) != want {
		t.Errorf("BandSettings: %s (%v)\nwant %s", b, err, want)
	}
	b, err = json.Marshal(RateOpts{BeaconKbps: 6000, NoCCK: true})
	if want := `{"BeaconKbps":6000,"NoCCK":true}`; err != nil || string(b) != want {
		t.Errorf("RateOpts: %s (%v), want %s", b, err, want)
	}
}

// The PMF hostapd is given is never below what the security mode needs
// (translate.PMFFloor), whatever the SSID's PMF says.
func TestKeyMgmtPMFAtLeastFloor(t *testing.T) {
	served := []string{SecWPA2, SecWPA3, SecWPA2WPA3, SecWPA2Ent, SecWPA3Ent}
	asked := []string{"", translate.PMFDisabled, translate.PMFOptional, translate.PMFRequired, "off", "0", "1", "2", "bogus"}
	for _, sec := range served {
		floor := translate.PMFLevel(translate.PMFFloor(sec))
		for _, pmf := range asked {
			mgmt, got := keyMgmt(SSID{Security: sec, PMF: pmf})
			if mgmt == "" {
				t.Errorf("%s: no key management", sec)
			}
			if got < floor {
				t.Errorf("%s with PMF %q: ieee80211w %d, below the mode's %d", sec, pmf, got, floor)
			}
			// and never below what was asked, in translate's words
			if want := translate.PMFLevel(pmf); got < want {
				t.Errorf("%s with PMF %q: ieee80211w %d, asked %d", sec, pmf, got, want)
			}
		}
	}
	// the modes with no key management here: open (no PMF at all, its
	// floor) and OWE, which this hostapd build does not serve
	if mgmt, pmf := keyMgmt(SSID{Security: SecOpen, PMF: translate.PMFRequired}); mgmt != "" || pmf != 0 || translate.PMFFloor(SecOpen) != translate.PMFDisabled {
		t.Errorf("open: key mgmt %q ieee80211w %d", mgmt, pmf)
	}
	if _, _, ok := normalizeSSID(SSID{ID: "w", SSID: "Home", Security: SecOWE}); ok {
		t.Error("an OWE SSID is served: its PMF floor (required) is not rendered by keyMgmt")
	}
}

// The tx power modes are translate's words; bcmwifi also reads "" (auto),
// "middle" (medium) and any case, and reports translate's word.
func TestTxPowerModeWords(t *testing.T) {
	for in, want := range map[string]string{
		translate.TxAuto: translate.TxAuto, translate.TxHigh: translate.TxHigh, translate.TxMedium: translate.TxMedium,
		translate.TxLow: translate.TxLow, translate.TxCustom: translate.TxCustom,
		"": translate.TxAuto, "middle": translate.TxMedium, "MIDDLE": translate.TxMedium, "Medium": translate.TxMedium,
		"AUTO": translate.TxAuto, "Low": translate.TxLow, "bogus": translate.TxHigh,
	} {
		r := Radio{TxPowerMode: in, TxPower: 10}
		q, _ := txpwrDegrade(r, 20)
		if mode, _ := txReportFor(r, 20, q); mode != want {
			t.Errorf("mode %q is reported as %q, want %q", in, mode, want)
		}
		// the same power as translate's word for it
		if wq, _ := txpwrDegrade(Radio{TxPowerMode: want, TxPower: 10}, 20); in != "bogus" && q != wq {
			t.Errorf("mode %q: degrade %d, %q gives %d", in, q, want, wq)
		}
	}
}

// GuestJumps is what wantJumps builds its jumps from (another platform's
// applier writes the same rules), and every guest chain's name starts with
// the prefix a live jump is recognised by.
func TestGuestJumps(t *testing.T) {
	got := GuestJumps("wl13")
	want := [][]string{
		{"FORWARD", "-i", "wl13", "-j", "UDECO-GIN"},
		{"FORWARD", "-o", "wl13", "-j", "UDECO-GOUT"},
		{"INPUT", "-i", "wl13", "-j", "UDECO-GIN"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GuestJumps = %v, want %v", got, want)
	}
	js := wantJumps([]string{"wl13", "wl03"})
	if len(js) != 6 {
		t.Fatalf("wantJumps: %v", js)
	}
	for i, j := range js {
		vif := []string{"wl13", "wl03"}[i/3]
		if !reflect.DeepEqual(j.rule(), GuestJumps(vif)[i%3]) {
			t.Errorf("wantJumps[%d] = %v, GuestJumps(%s)[%d] = %v", i, j.rule(), vif, i%3, GuestJumps(vif)[i%3])
		}
		if !reflect.DeepEqual(j.args("-D"), append([]string{"ebtables", "-D"}, j.rule()...)) {
			t.Errorf("args: %v", j.args("-D"))
		}
		// read back from a listing, it is the same jump
		if back := parseEbJumps(j.Chain, j.Dir+" "+j.Vif+" -j "+j.Target+" "); len(back) != 1 || back[0] != j {
			t.Errorf("parseEbJumps(%v) = %v", j, back)
		}
	}
	for _, c := range ourChains {
		if !strings.HasPrefix(c, guestChainPrefix) {
			t.Errorf("chain %s does not start with %s", c, guestChainPrefix)
		}
	}
	if !reflect.DeepEqual(ourChains, []string{GuestChainIn, GuestChainOut, GuestChainAuth}) ||
		GuestChainIn != "UDECO-GIN" || GuestChainOut != "UDECO-GOUT" || GuestChainAuth != "UDECO-GAUTH" {
		t.Errorf("guest chains %v", ourChains)
	}
	// the docs name the chains an operator sees in `ebtables -L`
	repotest.MustContain(t, "docs/deco/features/garage-parity.md", "chains `"+GuestChainIn+"`/`"+GuestChainOut+"` (and")
	repotest.MustContain(t, "docs/deco/features/garage-parity.md", "`"+GuestChainAuth+"` with the portal)")
	repotest.MustContain(t, "docs/deco/agent-design.md", "`UnauthorizeGuest` ("+GuestChainAuth+";")
}

// The security modes are translate's constants (their values are in the
// last-good Desired on flash: translate's test pins them).
func TestSecurityModesAreTranslates(t *testing.T) {
	for _, m := range []string{SecOpen, SecWPA2, SecWPA3, SecWPA2WPA3, SecWPA2Ent, SecWPA3Ent} {
		if _, notes, ok := normalizeSSID(SSID{ID: "w", SSID: "Home", Security: m, Passphrase: testPSK,
			Radius: &Radius{Auth: []RadiusServer{{IP: "192.168.0.9", Port: 1812, Secret: "s"}}}}); !ok {
			t.Errorf("%s is not served: %q", m, notes)
		}
	}
}

// ValidCountry is the rule for a driver country a config names
// (cmd/udeco-ap's driver_country_bands). The answers are what the config's
// own check gave while it wrote the rule itself: two ASCII letters in
// either case, or a table NoRadarCountry knows, with spaces around either
// ignored.
func TestValidCountry(t *testing.T) {
	for cc, want := range map[string]bool{
		"US": true, "us": true, "In": true, " us ": true, "\tDE\n": true,
		"#a": true, " #a ": true,
		"#A": false, "#b": false, "#": false, "##": false, "a#": false,
		"": false, " ": false, "U": false, "USA": false, "U1": false, "12": false, "U S": false, "U-": false,
		"\u00e9":  false, // two bytes, one letter that is not ASCII
		"\u00e9a": false,
	} {
		if got := ValidCountry(cc); got != want {
			t.Errorf("ValidCountry(%q) = %v, want %v", cc, got, want)
		}
		// what passes is a code NormCountry hands to wl: the '#' table as
		// it is, a two-letter code in upper case
		if n := NormCountry(cc); want && !NoRadarCountry(n) && (len(n) != 2 || n != strings.ToUpper(n)) {
			t.Errorf("NormCountry(%q) = %q", cc, n)
		}
	}
	if !ValidCountry("#a") || !NoRadarCountry("#a") {
		t.Error("the all-channels table is no longer a valid driver country")
	}
}
