// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"strings"
	"testing"
)

// "Restrict high-performance clients to 5 GHz" comes as
// wireless.N.no2ghz_oui=enabled on a WLAN's 2.4 GHz VAP (the Bedroom
// unit's system_cfg, 2026-11-20). A UAP acts on it only there (ubntbox:
// 2.4 GHz VAP with a same-SSID pair), so a 5 GHz VAP's value means nothing.
// It is read, never noted as not carried, and never makes the bands differ.
func TestNo2GHzIntent(t *testing.T) {
	for name, tc := range map[string]struct {
		extra []string
		want  bool
	}{
		"on 2.4 GHz":         {[]string{"wireless.1.no2ghz_oui=enabled", "wireless.2.no2ghz_oui=disabled"}, true},
		"off":                {[]string{"wireless.1.no2ghz_oui=disabled", "wireless.2.no2ghz_oui=disabled"}, false},
		"only on 5 GHz":      {[]string{"wireless.2.no2ghz_oui=enabled"}, false},
		"absent":             {nil, false},
		"the old seven ints": {[]string{"wireless.1.no2ghz_oui=0,0,0,3,2,16,30"}, false},
	} {
		t.Run(name, func(t *testing.T) {
			in, notes := IntentFromCfg(roamCfg(tc.extra...))
			if len(in.WLANs) != 1 {
				t.Fatalf("wlans %v", in.WLANs)
			}
			w := in.WLANs[0]
			if w.No2GHz != tc.want {
				t.Errorf("No2GHz %v, want %v", w.No2GHz, tc.want)
			}
			for _, n := range notes {
				if strings.Contains(n, "no2ghz") || strings.Contains(n, "differ") {
					t.Errorf("note %q", n)
				}
			}
			if tc.want && !strings.Contains(w.String(), "no2ghz") {
				t.Errorf("String: %s", w)
			}
		})
	}
}
