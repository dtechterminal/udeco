// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

// writeRadiusFilter adds the controller's RADIUS filter (Radius.FilterID,
// fw_caps 0x20000000) the way the U6 Pro's ubntbox does: hostapd's
// radius_auth_req_attr=11:s:<id>, RADIUS Filter-Id (attribute 11, a
// string) in every Access-Request. TP-Link's hostapd 2.9 on the X20 has the
// option (strings /sbin/hostapd: radius_auth_req_attr). The value is a
// plain token (translate.radiusFilterID); anything else is not written.
func writeRadiusFilter(w func(string, any), rad *Radius) {
	if rad == nil || rad.FilterID == "" || !plainToken(rad.FilterID) {
		return
	}
	w("radius_auth_req_attr", "11:s:"+rad.FilterID)
}

func plainToken(s string) bool {
	if len(s) > 64 {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}
