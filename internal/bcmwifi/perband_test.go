// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
	"testing"
)

// TestPerBandNoted: bcmwifi serves every band of an SSID with its SSID-wide
// settings, whatever SSID.PerBand holds (it does not call ForBand). A band
// whose own settings differ is noted by field name, as translate noted it
// before PerBand existed, so the operator sees what is not carried; the unit
// itself does not change.
func TestPerBandNoted(t *testing.T) {
	wide := SSID{ID: "w1", SSID: "Home", Bands: []string{"ng", "na"}, Enabled: true,
		Security: SecWPA2, Passphrase: testPSK, PMF: "disabled"}
	same := wide
	same.PerBand = map[string]BandSettings{"ng": wide.bandSettings(), "na": wide.bandSettings()}
	diff := wide
	na := wide.bandSettings()
	na.Security, na.PMF, na.RRM = SecWPA2WPA3, "optional", true
	diff.PerBand = map[string]BandSettings{"ng": wide.bandSettings(), "na": na}

	for _, c := range []struct {
		name string
		s    SSID
		note string // "" = no per-band note
	}{
		{"no PerBand", wide, ""},
		{"bands agree", same, ""},
		{"na differs", diff, "ssid w1: security, pmf, rrm differ on na: bcmwifi serves every band with the SSID-wide settings"},
	} {
		got, notes, ok := normalizeSSID(c.s)
		if !ok {
			t.Fatalf("%s: skipped: %q", c.name, notes)
		}
		n := strings.Join(notes, "\n")
		if c.note == "" && strings.Contains(n, "differ on") || c.note != "" && !strings.Contains(n, c.note) {
			t.Errorf("%s: notes %q", c.name, n)
		}
		if strings.Contains(n, " on ng") {
			t.Errorf("%s: ng noted though it agrees: %q", c.name, n)
		}
		if strings.Contains(n, testPSK) {
			t.Errorf("%s: note leaks the passphrase", c.name)
		}
		if got.Security != SecWPA2 || got.PMF != "disabled" || got.RRM {
			t.Errorf("%s: SSID-wide settings changed: %s %s rrm=%v", c.name, got.Security, got.PMF, got.RRM)
		}
	}

	// On a unit serving the SSID-wide settings, the same SSID with a
	// differing PerBand plans nothing (no conf, driver or bridge change)
	// and the plan carries the note.
	f := newFakeDev(t)
	a := newTestApplier(f, false)
	ctx := context.Background()
	d := Desired{Country: "IN", Radios: map[string]Radio{"ng": {Enabled: true, Channel: 6}, "na": {Enabled: true, Channel: 44, Width: 80}},
		SSIDs: []SSID{wide}}
	applyOK(t, a, d)
	f.reset()
	d.SSIDs = []SSID{diff}
	p, err := a.Plan(ctx, d)
	if err != nil || !p.Empty() {
		t.Fatalf("PerBand changed the plan (%v):\n%s", err, p)
	}
	if !strings.Contains(strings.Join(p.Notes, "\n"), "differ on na") {
		t.Errorf("plan notes %q", p.Notes)
	}
}
