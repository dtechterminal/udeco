// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"

	"github.com/antoniocosta/unifi-openwrt/internal/hs20"
)

// Hotspot 2.0 / Passpoint (docs/deco/features/hotspot2.md). The agent maps
// translate's Hotspot2 onto SSID.Hotspot2; bcmwifi writes it into the SSID's
// bss= section as hostapd 2.9 interworking/hs20 lines (internal/hs20). Every
// key written was found as a config keyword in the X20's /sbin/hostapd
// (CONFIG_INTERWORKING and CONFIG_HS20 are built in).
//
// What hostapd does with them on this driver is not verified on a unit:
//   - Beacons and probe responses: hostapd hands the Interworking (107),
//     Advertisement Protocol (108) and Roaming Consortium (111) elements to
//     the driver in the beacon tail and the probe/assoc response IEs. wl.ko
//     programs the Interworking element itself (wl_cfg80211_add_iw_ie, "set
//     interworking IE") and has an 802.11u module (wlc_11u_*, "iwap"/"iwrc"
//     element sizes); whether 108 and 111 reach the air is unknown. The HS
//     2.0 indication is a vendor element (50:6f:9a:10) and goes through the
//     vendor-IE path that already carries WPS/WMM.
//   - GAS/ANQP: hostapd answers GAS Initial Requests (public action frames)
//     it receives through nl80211. wl.ko forwards action frames with
//     cfg80211_rx_mgmt, but it also has its own GAS engine (wl_gas_*,
//     WLC_E_GAS_RQST_ANQP_QUERY) that may take them first.
// So the SSID itself (WPA-Enterprise, DGAF, PMF) is always correct, and the
// Passpoint discovery part needs the live checks in the feature doc.

// Hotspot2 is an SSID's Hotspot 2.0 advertisement (no secrets).
type Hotspot2 = hs20.Config

// normalizeHotspot2 checks s.Hotspot2 (nil: nothing to do). A non-empty
// result means the SSID must not be served: Hotspot 2.0 without
// WPA-Enterprise (hostapd refuses hs20=1 then, and the whole radio's hostapd
// with it), or a config hostapd would not load. PMF is raised to optional:
// Passpoint release 2 and later stations must use it (hostapd refuses them
// otherwise), and raising it never weakens the SSID.
func normalizeHotspot2(s *SSID, notes *[]string) string {
	if s.Hotspot2 == nil {
		return ""
	}
	if s.Security != SecWPA2Ent && s.Security != SecWPA3Ent {
		return fmt.Sprintf("Hotspot 2.0 needs WPA2/WPA3-Enterprise, security is %s", s.Security)
	}
	if _, err := s.Hotspot2.Lines(); err != nil {
		return "Hotspot 2.0: " + err.Error()
	}
	c := s.Hotspot2.Clone() // the caller's Desired is not changed
	s.Hotspot2 = c
	switch s.PMF {
	case "", "disabled", "off", "0":
		*notes = append(*notes, fmt.Sprintf("ssid %s: Hotspot 2.0: PMF raised to optional (Passpoint release 2+ stations need it)", s.ID))
		s.PMF = "optional"
	}
	if c.DisableDGAF && !s.ProxyARP {
		// hostapd's own proxy_arp cannot run on the vifs it creates here
		// (live fact F5); only the bridge's proxyarp_wifi answers ARP for
		// stations, on an SSID with proxy ARP.
		*notes = append(*notes, fmt.Sprintf("ssid %s: Hotspot 2.0: group-addressed frames are not delivered to stations (DGAF disabled) and no proxy ARP answers for them: turn on proxy ARP", s.ID))
	}
	return ""
}

// writeHotspot2 writes s.Hotspot2's lines into the current bss= section.
// normalizeHotspot2 has accepted it; an error here is a bug and fails the
// render rather than writing a line hostapd would refuse.
func writeHotspot2(w func(string, any), s SSID) error {
	if s.Hotspot2 == nil {
		return nil
	}
	if s.Security != SecWPA2Ent && s.Security != SecWPA3Ent {
		return fmt.Errorf("Hotspot 2.0 on a %s SSID", s.Security)
	}
	lines, err := s.Hotspot2.Lines()
	if err != nil {
		return err
	}
	for _, l := range lines {
		w(l.Key, l.Value)
	}
	return nil
}
