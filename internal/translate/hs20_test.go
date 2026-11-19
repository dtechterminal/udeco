// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

const eap = "aaa.1.wpa=2\naaa.1.wpa.key.1.mgmt=WPA-EAP\naaa.1.radius.auth.1.ip=10.0.0.5\naaa.1.radius.auth.1.secret=radius-secret-1"

// hs20Lines is a hotspot2conf as the controller writes it for aaa.1.
const hs20Lines = `aaa.1.hs20.status=enabled
aaa.1.hs20.access_network_type=2
aaa.1.hs20.internet=enabled
aaa.1.hs20.asra=disabled
aaa.1.hs20.esr=disabled
aaa.1.hs20.uesa=disabled
aaa.1.hs20.venue_group=2
aaa.1.hs20.venue_type=8
aaa.1.hs20.disable_dgaf=disabled
aaa.1.hs20.deauth_req_timeout=60
aaa.1.hs20.osu_ssid=OSU
aaa.1.hs20.network_availability=14
aaa.1.hs20.venue_name.1.lang=eng
aaa.1.hs20.venue_name.1.name=Cafe
aaa.1.hs20.nai_realm.1.status=enabled
aaa.1.hs20.nai_realm.1.encoding=0
aaa.1.hs20.nai_realm.1.name=example.com
aaa.1.hs20.nai_realm.1.eap_method=21
aaa.1.hs20.nai_realm.1.eap_method.auth.1.id=2
aaa.1.hs20.nai_realm.1.eap_method.auth.1.val=4
aaa.1.hs20.1.roaming_consortium=506f9a
aaa.1.hs20.3gpp.1.mcc=310
aaa.1.hs20.3gpp.1.mnc=026
aaa.1.hs20.friendly_name.1.language=eng
aaa.1.hs20.friendly_name.1.text=Operator
aaa.1.hs20.capab.1.protocol=6
aaa.1.hs20.capab.1.port=443
aaa.1.hs20.capab.1.status=open
aaa.1.osu.1.server_uri=https://osu.example.com/
aaa.1.osu.1.method_soap_xml_spp=enabled
aaa.1.osu.1.method_oma_dm=disabled
aaa.1.osu.1.friendly_name.1.language=eng
aaa.1.osu.1.friendly_name.1.text=SP
wireless.1.dgaf_disable=enabled`

func hs20Notes(notes []string) []string {
	var out []string
	for _, n := range notes {
		if strings.Contains(n, "hs20") || strings.Contains(n, "osu") || strings.Contains(n, "dgaf") || strings.Contains(n, "Hotspot") {
			out = append(out, n)
		}
	}
	return out
}

func TestIntentHotspot2(t *testing.T) {
	in, notes := IntentFromCfg(wlan(eap, hs20Lines))
	if len(in.WLANs) != 1 {
		t.Fatalf("wlans %v notes %q", in.WLANs, notes)
	}
	w := in.WLANs[0]
	h := w.Hotspot2
	if h == nil {
		t.Fatalf("no Hotspot2: notes %q", notes)
	}
	if w.Security != "wpa2-enterprise" || !h.Internet || !h.DisableDGAF || h.AccessNetworkType != 2 || len(h.NAIRealms) != 1 ||
		len(h.RoamingConsortia) != 1 || len(h.OSUProviders) != 1 || h.OSUSSID != "OSU" || h.IPAddrAvail != 14 {
		t.Errorf("hotspot2 %+v", *h)
	}
	// every hs20/osu/dgaf key is read: no "not carried"/unknown note
	if n := hs20Notes(notes); len(n) != 0 {
		t.Errorf("notes about Hotspot 2.0 keys: %q", n)
	}
	if s := w.String(); !strings.Contains(s, "hotspot2(") || strings.Contains(s, "radius-secret") {
		t.Errorf("String %q", s)
	}
	// a merged WLAN with the same hotspot2conf on both bands is not noted
	two := wlan(eap, hs20Lines, strings.ReplaceAll(strings.ReplaceAll(eap+"\n"+hs20Lines, "aaa.1.", "aaa.2."), "wireless.1.", "wireless.2."),
		"wireless.2.ssid=net", "wireless.2.id=w1", "wireless.2.parent=wifi0", "wireless.2.devname=ath2")
	in, notes = IntentFromCfg(two)
	if len(in.WLANs) != 1 || in.WLANs[0].Hotspot2 == nil || len(in.WLANs[0].Bands) != 2 {
		t.Fatalf("two bands: %v %q", in.WLANs, notes)
	}
	for _, n := range notes {
		if strings.Contains(n, "differ") {
			t.Errorf("note %q", n)
		}
	}
}

func TestIntentHotspot2Disabled(t *testing.T) {
	in, notes := IntentFromCfg(wlan(eap, "aaa.1.hs20.status=disabled"))
	if len(in.WLANs) != 1 || in.WLANs[0].Hotspot2 != nil {
		t.Fatalf("wlans %v", in.WLANs)
	}
	if n := hs20Notes(notes); len(n) != 0 {
		t.Errorf("notes %q", n)
	}
}

// The WLAN stays off (never built without what it asks for) for OSEN, for
// Terms and Conditions, and for Hotspot 2.0 on a non-enterprise WLAN.
func TestIntentHotspot2LeftOff(t *testing.T) {
	for _, tc := range []struct{ name, cfg, note string }{
		{"osen", wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=OSEN", "aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1", hs20Lines), "OSEN"},
		{"osen without hs20", wlan("aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=OSEN", "aaa.1.radius.auth.1.ip=10.0.0.5", "aaa.1.radius.auth.1.secret=radius-secret-1"), "OSEN"},
		{"terms", wlan(eap, hs20Lines, "aaa.1.hs20.t_c_filename=terms.html", "aaa.1.hs20.t_c_timestamp=1700000000"), "Terms and Conditions"},
		{"psk", wlan(psk, hs20Lines), "needs WPA-Enterprise"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in, notes := IntentFromCfg(tc.cfg)
			if len(in.WLANs) != 0 {
				t.Fatalf("not left off: %v", in.WLANs)
			}
			if !strings.Contains(strings.Join(notes, "\n"), tc.note) {
				t.Errorf("notes %q lack %q", notes, tc.note)
			}
		})
	}
}

// What is not carried is noted, by index.
func TestIntentHotspot2Notes(t *testing.T) {
	_, notes := IntentFromCfg(wlan(eap, hs20Lines, "aaa.1.hs20.icon.1.name=logo", "aaa.1.hs20.qos.status=enabled", "aaa.1.hs20.2.roaming_consortium=zz"))
	all := strings.Join(notes, "\n")
	for _, want := range []string{"icon(s) not sent", "QoS map not sent", "roaming consortium 2"} {
		if !strings.Contains(all, want) {
			t.Errorf("notes lack %q:\n%s", want, all)
		}
	}
}
