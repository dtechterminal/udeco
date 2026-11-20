// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"strings"
	"testing"

	"github.com/dtechterminal/udeco/internal/translate"
)

// The controller's RADIUS filter (aaa.N.filter_id) reaches bcmwifi's
// Desired, which writes it into hostapd (bcmwifi/radiusfilter.go).
func TestDesiredCarriesRadiusFilter(t *testing.T) {
	cfg := "radio.1.phyname=wifi0\nradio.1.ieee_mode=11nght20\nradio.2.phyname=wifi1\nradio.2.ieee_mode=11acvht80\n" +
		"wireless.1.ssid=Corp\nwireless.1.id=e1\nwireless.1.parent=wifi1\nwireless.1.devname=wifi1ap1\n" +
		"aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\naaa.1.radius.auth.1.ip=192.168.0.1\naaa.1.radius.auth.1.port=1812\n" +
		"aaa.1.radius.auth.1.secret=fake-radius-secret\naaa.1.filter_id=wpa-eap\n"
	in, _ := translate.IntentFromCfg(cfg)
	d, notes := desiredFrom(in)
	if len(d.SSIDs) != 1 || d.SSIDs[0].Radius == nil || d.SSIDs[0].Radius.FilterID != "wpa-eap" {
		t.Fatalf("desired %v", d.SSIDs)
	}
	if all := strings.Join(notes, "\n"); strings.Contains(all, "filter") {
		t.Errorf("filter noted: %s", all)
	}
}
