// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"strings"
)

// withoutSAE is s when SAE may not be served (Options.WPA3 off): a WPA2/WPA3
// transition SSID becomes WPA2 (its WPA2 clients join as before, WPA3-only
// clients cannot), a WPA3-only SSID is not served. WPA3-Enterprise is EAP,
// not SAE, and is left alone. ok=false: skip the SSID (note says why).
func withoutSAE(s SSID) (out SSID, note string, ok bool) {
	switch strings.ToLower(strings.TrimSpace(s.Security)) {
	case SecWPA2WPA3, "wpa3-transition", "wpa2-wpa3", "wpa2/wpa3":
		s.Security = SecWPA2
		return s, fmt.Sprintf("ssid %s: WPA2/WPA3 served as WPA2: SAE is off (config wpa3)", s.ID), true
	case SecWPA3:
		return s, fmt.Sprintf("ssid %s: WPA3 (SAE) is off (config wpa3), not served", s.ID), false
	}
	return s, "", true
}
