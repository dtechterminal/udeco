// SPDX-License-Identifier: GPL-2.0-or-later

package translate

// RADIUS filter (fw_caps 0x20000000, the controller's supportsRadiusFilter).
// For a WPA-Enterprise WLAN served by the console's own RADIUS server
// (site service SERVICES_RADIUS_SERVER), the controller adds
//
//	aaa.N.filter_id=wpa-eap     (or uid-wifi for a UniFi Identity WLAN)
//
// (Network 11.1.50, com.ubnt.service.config.XHjguBsIf; values from the enum
// com.ubnt.i.b.W.vFiJoQiuQjMZUx: mac-acl, uid-vpn, uid-wifi, wpa-eap, vpn).
// The U6 Pro's ubntbox turns it into hostapd's
// radius_auth_req_attr=11:s:<filter_id> (docs/reference/u6pro/actions-scans/
// U6 Pro ubntbox strings): RADIUS attribute 11 (Filter-Id) in every
// Access-Request, which tells the console's RADIUS server which policy the
// request is for.

// radiusFilterID returns the filter_id to send, "" when none or when the
// value is not a plain token (it goes into a hostapd conf line).
func radiusFilterID(v string, note func(string, ...any)) string {
	if v == "" {
		return ""
	}
	if len(v) > 64 {
		note("RADIUS filter_id longer than 64 characters: not sent")
		return ""
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.') {
			note("RADIUS filter_id %q is not a plain token: not sent", v)
			return ""
		}
	}
	return v
}
