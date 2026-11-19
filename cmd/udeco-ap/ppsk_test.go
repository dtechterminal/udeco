// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// The controller's PPSK keys (aaa.N.wpa.psk_file, what Network 11.1.50
// sends once WPA_PSK_FILE is claimed) reach bcmwifi's SSID unchanged; the
// keys never appear in notes or in a printed Desired.
func TestDesiredFromPPSK(t *testing.T) {
	const k1, k2 = "ppsk-agent-key-1", "ppsk-agent-key-2"
	cfg := testCfg + "aaa.1.dynamic_vlan=1\naaa.1.wpa.psk_file.status=enabled\n" +
		"aaa.1.wpa.psk_file.1.psk=" + k1 + "\naaa.1.wpa.psk_file.2.psk=" + k2 + "\naaa.1.wpa.psk_file.2.vlanid=30\n"
	in, inNotes := translate.IntentFromCfg(cfg)
	d, notes := desiredFrom(in)
	if len(d.SSIDs) != 1 {
		t.Fatalf("ssids %v (notes %q)", d.SSIDs, inNotes)
	}
	want := []bcmwifi.PSK{{Passphrase: k1}, {Passphrase: k2, VLAN: 30}}
	if got := d.SSIDs[0].PSKs; !reflect.DeepEqual(got, want) {
		t.Errorf("PSKs %v, want %v", got, want)
	}
	if d.SSIDs[0].Passphrase != fakePSK {
		t.Error("WLAN passphrase not carried next to the keys")
	}
	all := strings.Join(append(inNotes, notes...), "\n") + fmt.Sprintf("%v %+v %#v %v", d.SSIDs, d.SSIDs, d.SSIDs, in)
	for _, s := range []string{k1, k2} {
		if strings.Contains(all, s) {
			t.Fatalf("private key printed: %s", all)
		}
	}
}
