// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/models"
	"github.com/dtechterminal/udeco/internal/translate"
)

// Tests that hold this driver's planner and layout to what the other
// packages state about the same things: translate's Intent rules and the
// models the JCOW414 is reported as.

// one plans the single SSID s on band (the other radio is off) and returns
// its BSS, if served, with the notes.
func one(s bcmwifi.SSID, band string, sae bool) (BSS, bool, string) {
	s.ID, s.SSID, s.Enabled, s.Bands = "w", "Home", true, []string{band}
	ps, notes := plans(bcmwifi.Desired{Radios: map[string]bcmwifi.Radio{band: {Enabled: true}}, SSIDs: []bcmwifi.SSID{s}}, JCOW414, sae)
	if len(ps[band].BSS) != 1 {
		return BSS{}, false, strings.Join(notes, "\n")
	}
	return ps[band].BSS[0], true, strings.Join(notes, "\n")
}

// TestPassphraseLengthOnly: this planner refuses a passphrase by its length
// alone (8 to 64 bytes); translate.ValidWPAPassphrase (the rule of
// IntentFromCfg for WPA2 and WPA2/WPA3 WLANs, and of bcmwifi) also wants
// printable ASCII and, at 64, hex digits. The rows marked differ are served
// here though that rule refuses them. Not changed: one rule for both would
// stop serving such an SSID, which is the owner's call.
func TestPassphraseLengthOnly(t *testing.T) {
	rep := strings.Repeat
	for _, c := range []struct {
		name   string
		p      string
		served bool // by this planner
		valid  bool // translate.ValidWPAPassphrase
	}{
		{"7 characters", rep("a", 7), false, false},
		{"8 characters", rep("a", 8), true, true},
		{"63 characters", rep("a", 63), true, true},
		{"64 hex digits", rep("a", 64), true, true},
		{"65 characters", rep("a", 65), false, false},
		// differ
		{"64 characters, not hex", rep("g", 64), true, false},
		{"non-ASCII, 8 bytes", rep("a", 6) + "é", true, false},
		{"non-ASCII, 64 bytes", rep("é", 32), true, false},
		{"DEL", rep("a", 7) + "\x7f", true, false},
		{"a control character", rep("a", 7) + "\x1f", true, false},
	} {
		_, served, notes := one(bcmwifi.SSID{Security: translate.SecWPA2, Passphrase: c.p}, "na", false)
		if served != c.served {
			t.Errorf("%s: served %v, want %v (%s)", c.name, served, c.served, strings.ReplaceAll(notes, c.p, "<passphrase>"))
		}
		if got := translate.ValidWPAPassphrase(c.p); got != c.valid {
			t.Errorf("%s: translate.ValidWPAPassphrase %v, want %v", c.name, got, c.valid)
		}
		if !served && !strings.Contains(notes, "no valid passphrase: not served") {
			t.Errorf("%s: refused without the note", c.name)
		}
	}
}

// TestPMFAtLeastFloor: a served BSS never has less management frame
// protection than its mode needs (translate.PMFFloor), and what the
// controller asks above that is served, with three known exceptions, each
// noted in the plan:
//
//   - a WPA2/WPA3 transition BSS has PMF optional, fixed (PMFMFPC=1): PMF
//     required is not served on it;
//   - a transition SSID on a radio without SAE (or with WPA3 off) is served
//     as WPA2 with no PMF at all, though the transition's floor is optional;
//   - the MT7603 (2.4 GHz) profile has no PMF keys: nothing asked is served.
//
// Whether the first two should serve what is asked is the owner's call; the
// planner is as it was.
func TestPMFAtLeastFloor(t *testing.T) {
	servedMode := map[string]string{"OPEN": translate.SecOpen, "WPA2PSK": translate.SecWPA2,
		"WPA2PSKWPA3PSK": translate.SecWPA2WPA3, "WPA3PSK": translate.SecWPA3}
	seen := map[string]bool{}
	for _, rd := range JCOW414 {
		for _, sae := range []bool{false, true} {
			for _, sec := range []string{translate.SecOpen, translate.SecWPA2, translate.SecWPA2WPA3, translate.SecWPA3} {
				for _, asked := range []string{"", translate.PMFDisabled, translate.PMFOptional, translate.PMFRequired} {
					b, ok, notes := one(bcmwifi.SSID{Security: sec, PMF: asked, Passphrase: "good-pass-1"}, rd.Band, sae)
					name := rd.Band + " " + sec + " asked " + asked
					if !ok {
						if sec != translate.SecWPA3 || sae && rd.SAE {
							t.Errorf("%s: not served: %s", name, notes)
						}
						continue // WPA3 where there is no SAE: not served, so nothing below a floor
					}
					mode, known := servedMode[b.Auth]
					if !known {
						t.Fatalf("%s: AuthMode %q", name, b.Auth)
					}
					if floor := translate.PMFLevel(translate.PMFFloor(mode)); b.PMF < floor {
						t.Errorf("%s: served as %s with PMF %d, below that mode's %d", name, mode, b.PMF, floor)
					}
					want := pmfLevel(asked)
					if mode == translate.SecOpen {
						want = 0
					}
					exception := ""
					switch {
					case mode == translate.SecWPA2WPA3:
						exception = "transition: PMF optional, fixed"
						if b.PMF != 1 {
							t.Errorf("%s: transition served with PMF %d, want 1", name, b.PMF)
						}
					case sec == translate.SecWPA2WPA3 && mode == translate.SecWPA2:
						exception = "transition served as WPA2: no PMF"
						if b.PMF != 0 || !strings.Contains(notes, "served as WPA2 only") {
							t.Errorf("%s: PMF %d, notes %q", name, b.PMF, notes)
						}
					case !rd.SAE && mode != translate.SecOpen:
						exception = "no PMF keys in this radio's profile"
						if b.PMF != 0 {
							t.Errorf("%s: PMF %d on a radio without PMF", name, b.PMF)
						}
					}
					switch {
					case exception == "" && b.PMF != max(want, translate.PMFLevel(translate.PMFFloor(mode))):
						t.Errorf("%s: PMF %d, asked %d", name, b.PMF, want)
					case b.PMF < want:
						seen[exception] = true
						if n := "PMF " + asked + " not applied: served with PMF " + translate.PMFWord(b.PMF); !strings.Contains(notes, n) {
							t.Errorf("%s: PMF %d served for %d without the note %q: %q", name, b.PMF, want, n, notes)
						}
					}
				}
			}
		}
	}
	if len(seen) != 3 {
		t.Errorf("exceptions seen: %v, want the three of this test's comment", seen)
	}
}

// pmfLevel is translate's PMF level, with an unknown word as off.
func TestPMFLevelIsTranslates(t *testing.T) {
	for word, want := range map[string]int{"": 0, "bogus": 0, translate.PMFDisabled: 0, translate.PMFOptional: 1, translate.PMFRequired: 2} {
		if got := pmfLevel(word); got != want || want != max(translate.PMFLevel(word), 0) {
			t.Errorf("pmfLevel(%q) = %d, want %d (translate %d)", word, got, want, translate.PMFLevel(word))
		}
	}
}

// TestJCOW414HardwareFacts: what this layout says of the unit's radios is
// what the profiles of the models it is reported as say (internal/models):
// spatial streams, the lowest power, the power at 100 %, which radio does
// SAE, and the radio names. The layout is the driver's side of each fact;
// the profile is what the controller is told.
func TestJCOW414HardwareFacts(t *testing.T) {
	names := models.DecoAgentRadioNames()
	if len(JCOW414) != len(names) {
		t.Errorf("%d radios, %d radio names", len(JCOW414), len(names))
	}
	for _, rd := range JCOW414 {
		if names[rd.Band] != rd.Ifaces[0] {
			t.Errorf("%s: reported as radio %q, the first BSS netdev is %q", rd.Band, names[rd.Band], rd.Ifaces[0])
		}
		if rd.MaxTxDBm != models.JCOW414MaxTx(rd.Band) || rd.MaxTxDBm <= rd.MinTxDBm {
			t.Errorf("%s: %d..%d dBm, models.JCOW414MaxTx %d", rd.Band, rd.MinTxDBm, rd.MaxTxDBm, models.JCOW414MaxTx(rd.Band))
		}
	}
	if len(models.JCOW414Models) == 0 {
		t.Fatal("no JCOW414 models")
	}
	for code := range models.JCOW414Models {
		m, ok := models.Lookup(code)
		if !ok {
			t.Fatalf("%s is not in the catalogue", code)
		}
		p, ok := models.DecoAgentProfileWith(m, map[string]bool{}, models.DecoAgentFeatures{WPA3: true})
		if !ok || len(p.Radios) != len(JCOW414) {
			t.Fatalf("%s: profile ok=%v radios %+v", code, ok, p.Radios)
		}
		cat := map[string]int{} // the model's own maximum
		for _, r := range m.Radios {
			cat[r.Band] = r.MaxTx
		}
		for _, rd := range JCOW414 {
			r := p.Radios[rd.Band]
			if sae := r.RadioCaps2&models.RadioCap2WPA3 != 0; sae != rd.SAE {
				t.Errorf("%s %s: WPA3 claimed %v, the driver serves SAE %v", code, rd.Band, sae, rd.SAE)
			}
			if r.NSS != rd.NSS || r.RadioCaps != models.RadioCapsMIMO(rd.NSS) {
				t.Errorf("%s %s: %d streams (radio_caps %#x) reported, the radio has %d", code, rd.Band, r.NSS, r.RadioCaps, rd.NSS)
			}
			if r.MinTx != rd.MinTxDBm {
				t.Errorf("%s %s: min_txpower %d reported, the layout's is %d", code, rd.Band, r.MinTx, rd.MinTxDBm)
			}
			// the unit's power, unless the model's own maximum is lower
			if want := min(rd.MaxTxDBm, cat[rd.Band]); r.MaxTx != want {
				t.Errorf("%s %s: max_txpower %d reported, want %d (unit %d, model %d)", code, rd.Band, r.MaxTx, want, rd.MaxTxDBm, cat[rd.Band])
			}
		}
	}

	// and the capabilities the collector hands the agent are the layout's
	cp, err := NewCollector(CollectorOptions{}).Caps(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if cp.MaxBSS != 4 {
		t.Errorf("MaxBSS %d, want 4", cp.MaxBSS)
	}
	for _, rd := range JCOW414 {
		if len(rd.Ifaces) != cp.MaxBSS {
			t.Errorf("%s: %d BSS netdevs, MaxBSS %d", rd.Band, len(rd.Ifaces), cp.MaxBSS)
		}
		if b := cp.Bands[rd.Band]; b.NSS != rd.NSS || b.TxMinDBm != rd.MinTxDBm || b.TxMaxDBm != rd.MaxTxDBm {
			t.Errorf("%s: caps %d streams %d..%d dBm, layout %d and %d..%d", rd.Band, b.NSS, b.TxMinDBm, b.TxMaxDBm, rd.NSS, rd.MinTxDBm, rd.MaxTxDBm)
		}
	}
}

// The guest chains and the jumps into them are bcmwifi's (the same rules on
// both platforms): this applier has no names of its own for them.
func TestGuestChainsAreBcmwifis(t *testing.T) {
	r := bcmwifi.GuestEbtables(&bcmwifi.GuestPolicy{GatewayMAC: "00:11:22:33:44:55", GatewayIP: "192.168.0.1"})
	if r == nil || r.ChainIn != bcmwifi.GuestChainIn || r.ChainOut != bcmwifi.GuestChainOut || r.ChainAuth != bcmwifi.GuestChainAuth {
		t.Fatalf("guest rules %+v", r)
	}
	for _, j := range bcmwifi.GuestJumps("rai1") {
		if len(j) != 5 || j[2] != "rai1" || j[4] != bcmwifi.GuestChainIn && j[4] != bcmwifi.GuestChainOut {
			t.Errorf("jump %v", j)
		}
	}
}
