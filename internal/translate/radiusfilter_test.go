// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

// The controller's RADIUS filter on a WPA-Enterprise WLAN (aaa.N.filter_id,
// sent with fw_caps 0x20000000) is carried, not reported as an unknown key;
// a value that is not a plain token is dropped with a note.
func TestIntentRadiusFilter(t *testing.T) {
	ent := []string{"aaa.1.wpa=2", "aaa.1.wpa.key.1.mgmt=WPA-EAP", "aaa.1.radius.auth.1.ip=192.168.0.1",
		"aaa.1.radius.auth.1.port=1812", "aaa.1.radius.auth.1.secret=fake-radius-secret"}
	for _, c := range []struct{ value, want, note string }{
		{"wpa-eap", "wpa-eap", ""},
		{"uid-wifi", "uid-wifi", ""},
		{"wpa eap", "", "not a plain token"},
		{"wpa-eap;x=1", "", "not a plain token"},
	} {
		in, notes := IntentFromCfg(wlan(append(ent, "aaa.1.filter_id="+c.value)...))
		if len(in.WLANs) != 1 || in.WLANs[0].Radius == nil {
			t.Fatalf("%q: wlans %v notes %q", c.value, in.WLANs, notes)
		}
		if got := in.WLANs[0].Radius.FilterID; got != c.want {
			t.Errorf("%q: filter %q, want %q", c.value, got, c.want)
		}
		all := strings.Join(notes, "\n")
		if strings.Contains(all, "filter_id") && c.note == "" {
			t.Errorf("%q: filter_id noted: %s", c.value, all)
		}
		if c.note != "" && !strings.Contains(all, c.note) {
			t.Errorf("%q: notes lack %q: %s", c.value, c.note, all)
		}
	}
}
