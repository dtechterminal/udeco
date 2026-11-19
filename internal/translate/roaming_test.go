// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"reflect"
	"strings"
	"testing"
)

// roamCfg is a dual-band WLAN with 802.11v on both bands, as Network
// 11.1.50 writes it for a device claiming wifi_caps2 0x20; extra lines are
// appended (the assisted-roaming factory's keys go on the 5 GHz VAP only).
func roamCfg(extra ...string) string {
	return "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
		"aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=roam-pass-1\naaa.1.bss_transition=enabled\n" +
		"aaa.2.wpa=2\naaa.2.wpa.key.1.mgmt=WPA-PSK\naaa.2.wpa.psk=roam-pass-1\naaa.2.bss_transition=enabled\n" +
		"wireless.1.ssid=home\nwireless.1.id=w1\nwireless.1.parent=wifi0\nwireless.1.devname=ath0\n" +
		"wireless.2.ssid=home\nwireless.2.id=w1\nwireless.2.parent=wifi1\nwireless.2.devname=ath1\n" +
		strings.Join(extra, "\n") + "\n"
}

func TestRoamingAssistantIntent(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra []string
		want  map[string]int
		note  string // a note that must be there ("" = no roaming note)
	}{
		{"controller default on 5 GHz",
			[]string{"wireless.2.btm_disassoc.status=enabled", "wireless.2.btm_disassoc.threshold=-75"},
			map[string]int{"na": -75}, ""},
		{"UI value",
			[]string{"wireless.2.btm_disassoc.status=enabled", "wireless.2.btm_disassoc.threshold=-68"},
			map[string]int{"na": -68}, ""},
		{"off: a UAP template's status=disabled",
			[]string{"wireless.2.btm_disassoc.status=disabled"}, nil, ""},
		{"not sent", nil, nil, ""},
		{"junk threshold: the band's default",
			[]string{"wireless.2.btm_disassoc.status=enabled", "wireless.2.btm_disassoc.threshold=loud"},
			map[string]int{"na": -75}, `roaming assistant threshold "loud" not recognised: -75 dBm`},
		{"out of range threshold",
			[]string{"wireless.2.btm_disassoc.status=enabled", "wireless.2.btm_disassoc.threshold=-20"},
			map[string]int{"na": -75}, "not recognised"},
		{"missing threshold",
			[]string{"wireless.2.btm_disassoc.status=enabled"},
			map[string]int{"na": -75}, "not recognised"},
		{"no 802.11v on that band: off",
			[]string{"wireless.2.btm_disassoc.status=enabled", "wireless.2.btm_disassoc.threshold=-70", "aaa.2.bss_transition=disabled"},
			nil, "roaming assistant needs BSS transition (802.11v)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(roamCfg(tc.extra...))
			if len(in.WLANs) != 1 {
				t.Fatalf("WLANs %v notes %q", in.WLANs, notes)
			}
			if got := in.WLANs[0].RoamAssist; !reflect.DeepEqual(got, tc.want) {
				t.Errorf("RoamAssist %v, want %v", got, tc.want)
			}
			for _, n := range notes {
				// the keys are read: never "not supported" / "unknown"
				if strings.Contains(n, "btm_disassoc") {
					t.Errorf("btm_disassoc noted as not carried: %q", n)
				}
				if tc.note == "" && strings.Contains(n, "roaming assistant") {
					t.Errorf("unexpected note %q", n)
				}
			}
			if tc.note != "" && !hasNote(notes, tc.note) {
				t.Errorf("notes %q lack %q", notes, tc.note)
			}
			assertNoSecrets(t, in, notes, []string{"roam-pass-1"})
		})
	}
}

// The setting is per band: it never makes the merged WLAN's bands differ,
// and it is kept for the band it was sent on only.
func TestRoamingAssistantPerBand(t *testing.T) {
	in, notes := IntentFromCfg(roamCfg("wireless.2.btm_disassoc.status=enabled", "wireless.2.btm_disassoc.threshold=-72"))
	w := in.WLANs[0]
	if !reflect.DeepEqual(w.Bands, []string{"ng", "na"}) || !reflect.DeepEqual(w.RoamAssist, map[string]int{"na": -72}) {
		t.Errorf("got %v", w)
	}
	for _, n := range notes {
		if strings.Contains(n, "differ") {
			t.Errorf("per-band setting reported as differing: %q", n)
		}
	}
	if !strings.Contains(w.String(), "roam-assist=map[na:-72]") {
		t.Errorf("String: %s", w)
	}
	// a 6 GHz-style default when the threshold is junk on another band
	if d, ok := roamAssist(Cfg{"w.btm_disassoc.status": "enabled"}, "w.", "6e", true, func(string, ...any) {}); !ok || d != -88 {
		t.Errorf("6e default %d %t", d, ok)
	}
}
