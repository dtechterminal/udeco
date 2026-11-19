// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"strings"
	"testing"
)

// The controller's RADIUS filter reaches hostapd as the U6 Pro writes it:
// Filter-Id (attribute 11) in every Access-Request of that BSS; a value
// that is not a plain token never reaches the conf.
func TestHostapdRadiusFilter(t *testing.T) {
	ent := func(filter string) SSID {
		return SSID{ID: "e", SSID: "Corp", Bands: []string{"na"}, Enabled: true, Security: SecWPA2Ent,
			Radius: &Radius{Auth: []RadiusServer{{IP: "192.168.0.1", Port: 1812, Secret: testSecret}}, FilterID: filter}}
	}
	conf, _ := renderCase(t, "na", Radio{Enabled: true}, []SSID{ent("wpa-eap")}, nil)
	if n := strings.Count(conf, "\nradius_auth_req_attr=11:s:wpa-eap\n"); n != 1 {
		t.Errorf("radius_auth_req_attr lines: %d\n%s", n, conf)
	}
	// it belongs to the enterprise BSS, after its bss= line
	if i, j := strings.Index(conf, "\nbss="), strings.Index(conf, "radius_auth_req_attr"); i < 0 || j < i {
		t.Errorf("filter outside the BSS section:\n%s", conf)
	}
	for _, line := range strings.Split(strings.TrimSuffix(conf, "\n"), "\n") {
		if err := checkHostapdValue(line); err != nil {
			t.Error(err)
		}
	}
	for _, bad := range []string{"", "wpa eap", "a\nauth_server_addr=10.6.6.6"} {
		conf, _ := renderCase(t, "na", Radio{Enabled: true}, []SSID{ent(bad)}, nil)
		if strings.Contains(conf, "radius_auth_req_attr") || strings.Contains(conf, "10.6.6.6") {
			t.Errorf("filter %q written:\n%s", bad, conf)
		}
	}
}
