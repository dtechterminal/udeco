// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"os"
	"slices"
	"strings"
	"testing"
)

// mtkSystemCfg (testdata/system_cfg-ual6-mtk.txt) is a system_cfg shaped
// like the one UniFi Network sends a U6-Lite (a MediaTek model) whose radios
// are reported as ra0 and rai0: the .205 Deco's live configuration
// (2026-11-19: "Example Network" on both bands on the untagged Home network,
// "olive#" on 5 GHz on VLAN 3, both WPA2/WPA3 transition with 802.11r) plus
// a 5 GHz-only SSID on Home, the case the wifi0/wifi1 names mis-bridged, and
// WPA3 as the controller sends it once the radios claim radio_caps2 WPA3
// (wpa.key.1.mgmt=SAE, wpa3.support/transition). VAP devnames follow the
// controller's MediaTek scheme: ra0; rai0, rai1, rai2. The passphrases are
// fakes. cmd/udeco-ap's tests use the same file.
func mtkSystemCfg(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("testdata/system_cfg-ual6-mtk.txt")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// With MediaTek radio names every SSID has its own devname, so each 5 GHz
// SSID lands on its own network: the Home ones untagged, olive# on VLAN 3.
// WPA2/WPA3 (mgmt SAE + wpa3.transition) is carried as wpa2wpa3.
func TestIntentMediaTekDevnames(t *testing.T) {
	in, notes := IntentFromCfg(mtkSystemCfg(t))
	got := map[string]WLANIntent{}
	for _, w := range in.WLANs {
		got[w.SSID] = w
	}
	for _, c := range []struct {
		ssid  string
		bands []string
		vlan  int
	}{
		{"Example Network", []string{"ng", "na"}, 0},
		{"olive#", []string{"na"}, 3},
		{"Home 5G", []string{"na"}, 0},
	} {
		w, ok := got[c.ssid]
		if !ok {
			t.Errorf("%s: not in the intent (notes %q)", c.ssid, notes)
			continue
		}
		b := slices.Clone(w.Bands)
		slices.Sort(b)
		want := slices.Clone(c.bands)
		slices.Sort(want)
		if !slices.Equal(b, want) || w.VLAN != c.vlan {
			t.Errorf("%s: bands %v vlan %d, want %v vlan %d", c.ssid, w.Bands, w.VLAN, c.bands, c.vlan)
		}
		if w.Security != "wpa2wpa3" || w.PMF != "optional" || !w.FT {
			t.Errorf("%s: security %q pmf %q ft %v, want wpa2wpa3 optional true", c.ssid, w.Security, w.PMF, w.FT)
		}
	}
	if len(in.WLANs) != 3 {
		t.Errorf("%d WLANs, want 3", len(in.WLANs))
	}
	if r := in.Radios; r["ng"].Width != 20 || r["na"].Width != 40 || len(r) != 2 {
		t.Errorf("radios %+v", r)
	}
	all := strings.Join(notes, "\n")
	for _, bad := range []string{"vlan differ", "VAPs (", "is not on this AP", "Fake-Psk"} {
		if strings.Contains(all, bad) {
			t.Errorf("note with %q:\n%s", bad, all)
		}
	}
}

// The same configuration as the controller builds it for radios reported
// as wifi0/wifi1: every 5 GHz VAP is "wifi1", listed by both bridges. The
// collision is noted.
func TestIntentDuplicateDevnameNoted(t *testing.T) {
	cfg := strings.NewReplacer("=rai0\n", "=wifi1\n", "=rai1\n", "=wifi1\n", "=rai2\n", "=wifi1\n", "=ra0\n", "=wifi0\n").
		Replace(mtkSystemCfg(t))
	_, notes := IntentFromCfg(cfg)
	all := strings.Join(notes, "\n")
	if !strings.Contains(all, `devname "wifi1" names 3 VAPs (wireless.2, wireless.3, wireless.4)`) {
		t.Errorf("collision not noted:\n%s", all)
	}
	if strings.Contains(all, `devname "wifi0"`) {
		t.Errorf("a unique devname noted:\n%s", all)
	}
}
