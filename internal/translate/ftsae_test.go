// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

// ftIappKeys are fake per-WLAN iapp_keys (the controller's x_iapp_key, 32
// hex digits), by WLAN id of the MediaTek fixture.
var ftIappKeys = map[string]string{
	"2": "a1a2a3a4b1b2b3b4c1c2c3c4d1d2d3d4",
	"3": "ffeeddccbbaa99887766554433221100",
	"4": "4e4f50515253545556575859e0e1e2e3",
}

// withFTSAE turns the MediaTek fixture into what the controller sends once
// the radios claim radio_caps2 0x2 with fast roaming and WPA3 fast roaming
// on: wpa3.ft.status enabled and the WLAN's aaa.N.iapp_key on every VAP.
func withFTSAE(cfg string) string {
	var out []string
	for _, l := range strings.Split(cfg, "\n") {
		k, v, _ := strings.Cut(l, "=")
		if strings.HasSuffix(k, ".wpa3.ft.status") {
			l = k + "=enabled"
		}
		out = append(out, l)
		if strings.HasPrefix(k, "aaa.") && strings.HasSuffix(k, ".id") && ftIappKeys[v] != "" {
			out = append(out, strings.TrimSuffix(k, "id")+"iapp_key="+ftIappKeys[v])
		}
	}
	return strings.Join(out, "\n")
}

// WPA2/WPA3 transition WLANs with fast roaming and WPA3 fast roaming: each
// keeps 802.11r with FT-SAE and its own iapp_key on both bands; the keys
// never reach a note or a printed Intent.
func TestIntentFTSAE(t *testing.T) {
	cfg := withFTSAE(mtkSystemCfg(t))
	if n := strings.Count(cfg, ".iapp_key="); n != 4 {
		t.Fatalf("fixture: %d iapp_key lines", n)
	}
	in, notes := IntentFromCfg(cfg)
	if len(in.WLANs) != 3 {
		t.Fatalf("%d WLANs: %v", len(in.WLANs), in.WLANs)
	}
	for _, w := range in.WLANs {
		if w.Security != "wpa2wpa3" || !w.FT || !w.FTSAE || w.FTOverDS {
			t.Errorf("%s: %s ft=%t ftsae=%t overds=%t", w.SSID, w.Security, w.FT, w.FTSAE, w.FTOverDS)
		}
		if w.FTKey != ftIappKeys[w.ID] {
			t.Errorf("%s (WLAN %s): not its own iapp_key", w.SSID, w.ID)
		}
		if !strings.Contains(w.String(), "ft-sae") {
			t.Errorf("String lacks ft-sae: %s", w)
		}
	}
	if hasNote(notes, "fast-roam") || hasNote(notes, "differ") {
		t.Errorf("notes %q", notes)
	}
	var secrets []string
	for _, k := range ftIappKeys {
		secrets = append(secrets, k)
	}
	assertNoSecrets(t, in, notes, secrets)

	// The same WLANs before the controller's WPA3 fast roaming (radio_caps2
	// 0x2 not claimed): FT-PSK only, said so; the key is not carried
	// without 802.11r.
	off := strings.ReplaceAll(cfg, ".wpa3.ft.status=enabled", ".wpa3.ft.status=disabled")
	in, notes = IntentFromCfg(off)
	for _, w := range in.WLANs {
		if !w.FT || w.FTSAE {
			t.Errorf("%s: ft=%t ftsae=%t", w.SSID, w.FT, w.FTSAE)
		}
	}
	if !hasNote(notes, "WPA3 clients do not fast-roam") {
		t.Errorf("notes %q", notes)
	}
	noFT := strings.ReplaceAll(cfg, ".ft.status=enabled\n", ".ft.status=disabled\n")
	in, _ = IntentFromCfg(noFT)
	for _, w := range in.WLANs {
		if w.FT || w.FTSAE || w.FTKey != "" {
			t.Errorf("%s: 802.11r off but ft=%t ftsae=%t key carried=%t", w.SSID, w.FT, w.FTSAE, w.FTKey != "")
		}
	}

	// FT over the DS as ubntbox reads it (aaa.N.ft_over_ds, an integer).
	ds := strings.ReplaceAll(cfg, "aaa.2.ft.status=enabled\n", "aaa.2.ft.status=enabled\naaa.2.ft_over_ds=1\n")
	ds = strings.ReplaceAll(ds, "aaa.1.ft.status=enabled\n", "aaa.1.ft.status=enabled\naaa.1.ft_over_ds=1\n")
	in, _ = IntentFromCfg(ds)
	for _, w := range in.WLANs {
		if want := w.ID == "2"; w.FTOverDS != want {
			t.Errorf("%s: over-DS %t, want %t", w.SSID, w.FTOverDS, want)
		}
	}
}
