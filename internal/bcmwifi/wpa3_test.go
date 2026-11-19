// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"strings"
	"testing"
)

// Options.WPA3 off (noSAE): a WPA2/WPA3 SSID is placed as WPA2, a
// WPA3-only one is not served, WPA3-Enterprise (EAP, not SAE) is left
// alone; on, all three keep their security.
func TestWPA3Switch(t *testing.T) {
	d := Desired{Radios: map[string]Radio{"ng": {Enabled: true}}, SSIDs: []SSID{
		{ID: "a", SSID: "Trans", Bands: []string{"ng"}, Enabled: true, Security: "WPA2-WPA3", Passphrase: "transition-pass"},
		{ID: "b", SSID: "Sae", Bands: []string{"ng"}, Enabled: true, Security: SecWPA3, Passphrase: "sae-only-pass"},
		{ID: "c", SSID: "Ent", Bands: []string{"ng"}, Enabled: true, Security: SecWPA3Ent,
			Radius: &Radius{Auth: []RadiusServer{{IP: "192.168.0.1", Port: 1812, Secret: "radius-secret"}}}},
	}}
	sec := func(l *layout) map[string]string {
		m := map[string]string{}
		for _, u := range l.radio("ng").Used {
			m[u.SSID.ID] = u.SSID.Security
		}
		return m
	}
	l := planLayout(d, fixtureVifs, layoutOpts{anyVifOnLAN: true, noSAE: true})
	got := sec(l)
	if got["a"] != SecWPA2 || got["b"] != "" || got["c"] != SecWPA3Ent || len(got) != 2 {
		t.Errorf("SAE off: %v", got)
	}
	notes := strings.Join(l.Notes, "\n")
	for _, w := range []string{"ssid a: WPA2/WPA3 served as WPA2", "ssid b: WPA3 (SAE) is off (config wpa3), not served"} {
		if !strings.Contains(notes, w) {
			t.Errorf("notes lack %q:\n%s", w, notes)
		}
	}
	if strings.Contains(notes, "transition-pass") || strings.Contains(notes, "sae-only-pass") {
		t.Error("a note leaks a passphrase")
	}
	l = planLayout(d, fixtureVifs, layoutOpts{anyVifOnLAN: true})
	if got := sec(l); got["a"] != SecWPA2WPA3 || got["b"] != SecWPA3 || got["c"] != SecWPA3Ent {
		t.Errorf("SAE on: %v (notes %q)", got, l.Notes)
	}
}
