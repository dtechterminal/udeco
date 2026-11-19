// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

const wlansCfg = `radio.1.phyname=wifi0
radio.1.ieee_mode=11nght20
radio.2.phyname=wifi1
radio.2.ieee_mode=11naht80
radio.2.status=disabled
aaa.1.ssid=home
aaa.1.wpa=2
aaa.1.wpa.key.1.mgmt=SAE
aaa.1.wpa3.transition=enabled
aaa.1.wpa.psk=s3cret-pass
aaa.1.ft.status=enabled
wireless.1.ssid=home
wireless.1.id=w1
wireless.1.parent=wifi0
wireless.1.devname=ath0
wireless.1.usage=user
aaa.2.ssid=visitors
aaa.2.is_guest=true
aaa.2.wpa=2
aaa.2.wpa.key.1.mgmt=WPA-PSK
aaa.2.wpa.psk=guest-pass-1
wireless.2.ssid=visitors
wireless.2.parent=wifi1
wireless.2.devname=ath1
wireless.2.hide_ssid=true
wireless.2.status=disabled
wireless.2.l2_isolation=enabled
wireless.3.ssid=vwire-x
wireless.3.parent=wifi1
wireless.3.vwire=enabled
aaa.4.ssid=corp
aaa.4.wpa=2
aaa.4.wpa.key.1.mgmt=WPA-EAP
wireless.4.ssid=corp
wireless.4.parent=wifi2
wireless.5.ssid=element-x
wireless.5.parent=wifi0
wireless.5.element_adopt=enabled
`

func TestWLANs(t *testing.T) {
	got := WLANs(ParseCfg(wlansCfg))
	if len(got) != 5 {
		t.Fatalf("got %d WLANs: %v", len(got), got)
	}
	tests := []struct {
		i                                       int
		ssid, band, enc                         string
		enabled, hidden, guest, mesh, elem, off bool
		features                                string
	}{
		{0, "home", "2g", "sae-mixed", true, false, false, false, false, false, "802.11r"},
		{1, "visitors", "5g", "psk2+ccmp", false, true, true, false, false, true, "l2-isolation"},
		{2, "vwire-x", "5g", "none", true, false, false, true, false, true, ""},
		{3, "corp", "6g", "", true, false, false, false, false, false, ""},
		{4, "element-x", "2g", "none", true, false, false, false, true, false, ""},
	}
	for _, tt := range tests {
		w := got[tt.i]
		if w.SSID != tt.ssid || w.Band != tt.band || w.Encryption != tt.enc || w.Enabled != tt.enabled ||
			w.Hidden != tt.hidden || w.Guest != tt.guest || w.Mesh != tt.mesh || w.ElementAdopt != tt.elem ||
			w.RadioOff != tt.off || strings.Join(w.Features, ",") != tt.features {
			t.Errorf("wlan %d: %+v", tt.i, w)
		}
	}
	if got[0].PSK != "s3cret-pass" || got[0].ID != "w1" || got[0].Devname != "ath0" {
		t.Errorf("wlan 0 fields: %s", got[0])
	}
	if got[3].EncNote == "" {
		t.Errorf("enterprise WLAN should carry a note")
	}
}

func TestWLANStringAndMaskHideSecrets(t *testing.T) {
	cfg := ParseCfg(wlansCfg)
	for _, w := range WLANs(cfg) {
		if s := w.String(); strings.Contains(s, "s3cret-pass") || strings.Contains(s, "guest-pass-1") {
			t.Fatalf("secret in %s", s)
		}
	}
	if m := Mask("s3cret-pass"); strings.Contains(m, "s3cret") || m == Mask("other") || Mask("") != "''" {
		t.Fatalf("Mask: %q", m)
	}
	mc := MaskCfg(cfg)
	if mc["aaa.1.wpa.psk"] == "s3cret-pass" || mc["aaa.1.ssid"] != "home" || cfg["aaa.1.wpa.psk"] != "s3cret-pass" {
		t.Fatalf("MaskCfg: %v", mc)
	}
	for k, want := range map[string]bool{"aaa.1.wpa.psk": true, "syslog.remote.key": true, "users.1.password": true,
		"snmp.community": true, "aaa.1.wpa.key.1.mgmt": false, "wireless.1.ssid": false} {
		if IsSecretKey(k) != want {
			t.Errorf("IsSecretKey(%s) != %t", k, want)
		}
	}
}

// WLANs is additive: Plan's output for the same config must not change.
func TestWLANsLeavesPlanAlone(t *testing.T) {
	c := ParseCfg(cfg)
	before := Plan(c, ParseUCI(cur), Features{})
	_ = WLANs(c)
	after := Plan(c, ParseUCI(cur), Features{})
	if len(before.Ops) != len(after.Ops) {
		t.Fatalf("plan changed: %d vs %d ops", len(before.Ops), len(after.Ops))
	}
}
