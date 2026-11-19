// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

// The controller's PPSK config factory output (com.ubnt.service.aF, Network
// 11.1.50) for a WPA2 WLAN with three keys: one on the untagged LAN
// (VLAN 1, vlanid omitted) and two on VLAN 20. Fake passphrases.
const ppskCfg = "aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-PSK\naaa.1.wpa.psk=good-pass-1\n" +
	"aaa.1.dynamic_vlan=1\naaa.1.wpa.psk_file.status=enabled\n" +
	"aaa.1.wpa.psk_file.1.psk=ppsk-lan-pass\n" +
	"aaa.1.wpa.psk_file.2.psk=ppsk-iot-pass\naaa.1.wpa.psk_file.2.vlanid=20\n" +
	"aaa.1.wpa.psk_file.10.psk=ppsk-iot-pass2\naaa.1.wpa.psk_file.10.vlanid=20"

func TestIntentPPSK(t *testing.T) {
	secrets := []string{"good-pass-1", "ppsk-lan-pass", "ppsk-iot-pass", "ppsk-iot-pass2", "bad\tpass-x"}
	tests := []struct {
		name  string
		cfg   string
		sec   string // "" = left off
		pass  string
		psks  []PSK
		notes []string
	}{
		{name: "controller keys", cfg: wlan(ppskCfg), sec: "wpa2", pass: "good-pass-1",
			psks:  []PSK{{Passphrase: "ppsk-lan-pass"}, {Passphrase: "ppsk-iot-pass", VLAN: 20}, {Passphrase: "ppsk-iot-pass2", VLAN: 20}},
			notes: []string{"not supported, ignored: dynamic_vlan=1"}},
		{name: "no wlan passphrase", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk=",
			"aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.psk=ppsk-lan-pass"),
			sec: "wpa2", pass: "", psks: []PSK{{Passphrase: "ppsk-lan-pass"}}},
		{name: "ubntbox fields", cfg: wlan(psk, "aaa.1.wpa.psk_file.status=enabled",
			"aaa.1.wpa.psk_file.1.psk="+strings.Repeat("Ab", 32), "aaa.1.wpa.psk_file.1.mac=AA-BB-CC-00-00-01", "aaa.1.wpa.psk_file.1.keyid=guest-1",
			"aaa.1.wpa.psk_file.2.psk=ppsk-lan-pass", "aaa.1.wpa.psk_file.2.mac=00:00:00:00:00:00", "aaa.1.wpa.psk_file.2.vlanid=1"),
			sec: "wpa2", pass: "good-pass-1",
			psks: []PSK{{Passphrase: strings.Repeat("Ab", 32), MAC: "aa:bb:cc:00:00:01", KeyID: "guest-1"}, {Passphrase: "ppsk-lan-pass"}}},
		{name: "bad entries dropped", cfg: wlan(psk, "aaa.1.wpa.psk_file.status=enabled",
			"aaa.1.wpa.psk_file.1.psk=short", "aaa.1.wpa.psk_file.2.psk=bad\tpass-x", "aaa.1.wpa.psk_file.3.psk=ppsk-lan-pass",
			"aaa.1.wpa.psk_file.3.vlanid=5000", "aaa.1.wpa.psk_file.4.psk=ppsk-lan-pass", "aaa.1.wpa.psk_file.4.mac=nope",
			"aaa.1.wpa.psk_file.5.psk=ppsk-iot-pass", "aaa.1.wpa.psk_file.5.keyid=has space",
			"aaa.1.wpa.psk_file.6.psk=ppsk-iot-pass2", "aaa.1.wpa.psk_file.6.status=disabled"),
			sec: "wpa2", pass: "good-pass-1", psks: []PSK{{Passphrase: "ppsk-iot-pass"}},
			notes: []string{"key 1 is not 8-63", "key 2 is not 8-63", "key 3: VLAN \"5000\"", "key 4: station MAC", "key 5: key id not usable"}},
		{name: "transition carries keys", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE WPA-PSK", "aaa.1.wpa.psk=good-pass-1",
			"aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.psk=ppsk-lan-pass"),
			sec: "wpa2wpa3", pass: "good-pass-1", psks: []PSK{{Passphrase: "ppsk-lan-pass"}}},
		// left off, never weaker
		{name: "wpa3 only", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=SAE", "aaa.1.wpa.psk=good-pass-1",
			"aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.psk=ppsk-lan-pass"),
			notes: []string{"key file is WPA2-PSK only: left off"}},
		{name: "nothing usable", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK",
			"aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.psk=short"),
			notes: []string{"none usable and no WLAN passphrase: left off"}},
		{name: "never open", cfg: wlan("aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.psk=ppsk-lan-pass"),
			notes: []string{"not built as open"}},
		{name: "psk radius still refused", cfg: wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-PSK", "aaa.1.wpa.psk_radius=enabled",
			"aaa.1.wpa.psk_file.status=enabled", "aaa.1.wpa.psk_file.1.psk=ppsk-lan-pass"),
			sec: "wpa2", pass: "", psks: []PSK{{Passphrase: "ppsk-lan-pass"}}, notes: []string{"(PPSK) are not supported: the WLAN's passphrase only"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			all := strings.Join(notes, "\n") + "\n" + fmt.Sprint(in) + fmt.Sprintf("%v %+v %#v", in.WLANs, in.WLANs, in.WLANs)
			for _, s := range secrets {
				if strings.Contains(all, s) {
					t.Errorf("secret %q printed in notes or String: %s", s, all)
				}
			}
			for _, n := range tc.notes {
				if !strings.Contains(strings.Join(notes, "\n"), n) {
					t.Errorf("note %q missing in %q", n, notes)
				}
			}
			if tc.sec == "" {
				if len(in.WLANs) != 0 {
					t.Fatalf("not left off: %v", in.WLANs)
				}
				return
			}
			if len(in.WLANs) != 1 {
				t.Fatalf("wlans %v, notes %q", in.WLANs, notes)
			}
			w := in.WLANs[0]
			if w.Security != tc.sec || w.Passphrase != tc.pass {
				t.Errorf("security %s passphrase-set %t, want %s %t", w.Security, w.Passphrase != "", tc.sec, tc.pass != "")
			}
			if !reflect.DeepEqual(w.PSKs, tc.psks) {
				t.Errorf("PSKs %v, want %v", w.PSKs, tc.psks)
			}
		})
	}
}
