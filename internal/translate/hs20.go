// SPDX-License-Identifier: GPL-2.0-or-later

package translate

import (
	"regexp"
	"slices"

	"github.com/antoniocosta/unifi-openwrt/internal/hs20"
)

// Hotspot 2.0 / Passpoint (fw_caps 0x800000, the controller's
// supportHotspot2; docs/deco/features/hotspot2.md). Without the bit the
// controller skips a WLAN with hotspot2conf_enabled, or with OSEN security,
// altogether ("Hotspot 2 cannot provision OSEN ..."). With it, a
// WPA-Enterprise WLAN gets aaa.N.hs20.* (status, access network type, venue,
// NAI realms, roaming consortia, 3GPP networks, operator names, connection
// capabilities, WAN metrics, ...) plus aaa.N.osu.* (online sign-up
// providers) and wireless.N.dgaf_disable. Every other WPA-Enterprise WLAN
// carries aaa.N.hs20.status=disabled. internal/hs20 parses and renders it.

// Hotspot2 is a WLAN's Hotspot 2.0 advertisement (no secrets).
type Hotspot2 = hs20.Config

func init() {
	// Every hs20/osu key is read by wlanHotspot2 (internal/hs20.Parse), which
	// notes what it does not carry.
	keyPatterns["aaa"] = append(keyPatterns["aaa"],
		struct {
			re *regexp.Regexp
			r  rule
		}{regexp.MustCompile(`^(hs20|osu)\.`), rRead})
	wirelessRules["dgaf_disable"] = rRead
}

// wlanHotspot2 sets x.Hotspot2 from aaa.N.hs20.* / aaa.N.osu.*. A non-empty
// result means the VAP must stay off: OSEN (the OSU server-only network,
// which this hostapd has but which is not built here), Hotspot 2.0 on a
// WLAN that is not WPA-Enterprise (hostapd refuses hs20=1 without
// WPA2-Enterprise/CCMP), or a part that would leave it weaker if dropped.
func wlanHotspot2(cfg Cfg, w, a string, x *WLANIntent, note func(string, ...any)) string {
	if slices.Contains(wpaKeyMgmt(cfg, a, wpaKeySent(cfg, a)), "OSEN") {
		return "OSEN (Hotspot 2.0 online sign-up security) is not supported"
	}
	c, notes, off := hs20.Parse(cfg, a, w)
	for _, n := range notes {
		note("%s", n)
	}
	if off != "" {
		return off
	}
	if c == nil {
		return ""
	}
	if x.Security != SecWPA2Ent && x.Security != SecWPA3Ent {
		return "Hotspot 2.0 needs WPA-Enterprise (security here: " + x.Security + ")"
	}
	x.Hotspot2 = c
	return ""
}
