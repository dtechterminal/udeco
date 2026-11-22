// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/ftpeer"
)

// 802.11r (fast BSS transition) for the agent's SSIDs.
//
// FT-PSK needs nothing from the other APs: hostapd derives PMK-R0/R1 from
// the PSK itself (ft_psk_generate_local, what TP-Link's psk2ft does). FT-SAE
// cannot: the PMK comes out of the SAE exchange with the first AP (the
// R0KH), so the target AP (R1KH) has to fetch PMK-R1 from it over the LAN
// (RRB, ethertype 0x88b7, on the BSS's bridge), or have it pushed ahead of
// the roam. Those transfers are encrypted with a key the APs share: the
// controller's per-WLAN iapp_key (aaa.N.iapp_key, the WLAN's x_iapp_key, 32
// hex digits, sent to every AP of the WLAN while iapp_enabled). hostapd 2.9
// (the Deco's) takes a 128-bit key and stretches it with its "FT OLDKEY"
// KDF (rkh_derive_key), as a newer UniFi hostapd does.
//
// A UniFi AP (ubntbox) lists the other APs as wildcards,
// r0kh=ff:ff:ff:ff:ff:ff * <key> and r1kh=00:00:00:00:00:00
// 00:00:00:00:00:00 <key>. hostapd 2.9 cannot use them as the target AP: a
// wildcard R0KH's SEQ_REQ and PULL go to ff:ff:ff:ff:ff:ff through
// hostapd_wpa_auth_send_oui, whose hostapd_wpa_auth_oui_iter hands a
// multicast frame to the first other BSS of the process (here always the
// placeholder, interface=) and returns 1, so eth_p_oui_send never runs and
// the PULL never reaches another AP (fixed in 2.10). So every BSS lists
// the other units' key holders explicitly, one pair per peer BSS:
//
//	r0kh=<peer BSSID> <peer R0KH-ID (its nas_identifier)> <key>
//	r1kh=<peer BSSID> <peer R1KH-ID (its r1_key_holder)> <key>
//	pmk_r1_push=1
//
// A unicast frame is sent (oui_iter only takes it for a BSS of the same
// process whose own address it is), and pmk_r1_push pushes the PMK-R1 to
// every listed R1KH after the initial SAE. The peers come from
// internal/ftpeer (the agents announce their key holders to each other,
// authenticated with a key derived from the same iapp_key) through
// SetFTPeers; those known when a hostapd starts are in its conf, later
// ones are added to the running hostapd (SyncFTPeers, ftpeers.go).
//
// Same unit, other radio: each radio runs its own hostapd, and a frame
// one sends on the bridge to the other's BSSID is not looped back to the
// other process's packet socket (the bridge delivers it to that BSSID's
// own port, the wl vif), so one unit's radios cannot hand a PMK-R1 to each
// other. They do not list each other, and an FT-SAE BSS gets a mobility
// domain of its own band (bandMobilityDomain): a client moving between
// the two radios of one unit sees another mobility domain and does a full
// SAE instead of an FT attempt that would fail. Roams between units on the
// same band are FT-SAE. (One hostapd process for both radios would allow
// it, at the cost of per-radio restarts and rollback; see
// docs/deco/features/ft-sae.md.)
//
// R0KH-ID (nas_identifier) and R1KH-ID (r1_key_holder) are the BSSID,
// unique per BSS. The MDID is the controller's aaa.N.mobility_domain when
// sent (10.6.109 never sends one), else derived from the SSID, per band
// for FT-SAE (ssidMDID).

// validFTKey: what hostapd 2.9 accepts as an r0kh/r1kh key, 64 hex digits
// or the 32 of a 128-bit key (stretched with "FT OLDKEY").
func validFTKey(k string) bool { return (len(k) == 32 || len(k) == 64) && isHex(k) }

// validMDID: 4 hex digits.
func validMDID(md string) bool { return len(md) == 4 && isHex(md) }

// normalizeFT settles s.FT, s.FTSAE, s.FTOverDS and s.MobilityDomain for
// s.Security (already normalized). Notes never contain the key.
func normalizeFT(s SSID, notes []string) (SSID, []string) {
	note := func(format string, args ...any) {
		notes = append(notes, fmt.Sprintf("ssid %s: ", s.ID)+fmt.Sprintf(format, args...))
	}
	sae := s.Security == SecWPA3 || s.Security == SecWPA2WPA3
	saeFT := s.FT && sae && s.FTSAE && validFTKey(s.FTKey)
	if s.FT {
		switch s.Security {
		case SecWPA3:
			if !saeFT {
				note("802.11r off: %s", ftSAEWhy(s))
				s.FT = false
			}
		case SecWPA2WPA3:
			if !saeFT {
				note("802.11r for WPA2 clients only (FT-PSK); SAE clients do not roam fast: %s", ftSAEWhy(s))
			}
		case SecWPA2Ent, SecWPA3Ent:
			note("802.11r off: FT-EAP needs a live test with this hostapd and driver first, not built")
			s.FT = false
		case SecOpen:
			s.FT = false
		}
	}
	s.FTSAE = s.FT && saeFT
	if !s.FTSAE {
		s.FTKey = "" // used only for FT-SAE: kept out of the conf
	}
	if !s.FT {
		s.FTOverDS = false
		s.MobilityDomain = ""
		return s, notes
	}
	if md := strings.ToLower(s.MobilityDomain); md != "" && !validMDID(md) {
		note("802.11r mobility domain %q is not 4 hex digits: derived from the SSID", s.MobilityDomain)
		s.MobilityDomain = ""
	} else {
		s.MobilityDomain = md
		if md != "" && s.FTSAE && len(s.Bands) != 1 {
			note("802.11r mobility domain %s from the controller is used on both bands: an SAE client moving between this unit's two radios tries FT-SAE, which fails here (one hostapd per radio cannot pass the PMK-R1), and falls back to a full SAE", md)
		}
	}
	return s, notes
}

// ftSAEWhy says why FT-SAE is not built for s.
func ftSAEWhy(s SSID) string {
	switch {
	case !s.FTSAE:
		return "FT-SAE needs the controller's WPA3 fast roaming (wpa3.ft.status), which it sends only to an AP claiming radio_caps2 0x2"
	case s.FTKey == "":
		return "FT-SAE needs the controller's per-WLAN key (iapp_key) for the PMK-R1 transfers between APs, none sent"
	default:
		return "the controller's per-WLAN key (iapp_key) is not 32 or 64 hex digits, FT-SAE not built"
	}
}

// ssidMDID is the 802.11r mobility domain of s's BSS on band: the
// controller's when it sent a valid one, else derived from the SSID, per
// band when the SSID serves FT-SAE (see "Same unit, other radio" above).
// Every unit derives the same value, so a roam between units on one band
// stays in one mobility domain.
func ssidMDID(s SSID, band string) uint16 {
	if validMDID(s.MobilityDomain) {
		if v, err := strconv.ParseUint(s.MobilityDomain, 16, 16); err == nil {
			return uint16(v)
		}
	}
	if s.FTSAE {
		return bandMobilityDomain(s.SSID, band)
	}
	return mobilityDomain(s.SSID)
}

// SSIDMDID is the mobility domain the Decos serve s with on band ("ng",
// "na"): the Garage (mtkwifi) uses it too, so clients roam between them
// with 802.11r.
func SSIDMDID(s SSID, band string) uint16 { return ssidMDID(s, band) }

// NormalizeFT is what a Deco makes of s's 802.11r (s.Security already
// one of the Sec* words): FT off where it builds none, FT-SAE only with a
// usable key, the controller's mobility domain kept when valid. The notes
// say what is not built (never the key).
func NormalizeFT(s SSID) (SSID, []string) { return normalizeFT(s, nil) }

// ValidFTKey: k is a usable iapp_key (32 or 64 hex digits).
func ValidFTKey(k string) bool { return validFTKey(k) }

// bandMobilityDomain derives a per-band MDID from the SSID; the two bands
// never share one.
func bandMobilityDomain(ssid, band string) uint16 {
	md := mobilityDomain(ssid + "\x00" + band)
	if band != "ng" && md == mobilityDomain(ssid+"\x00ng") {
		if md ^= 1; md == 0 {
			md = 2
		}
	}
	return md
}

// writeFT writes the 802.11r lines of a BSS on band whose SSID s has FT
// on. kh is the BSSID as 12 hex digits (R0KH-ID and R1KH-ID). hostapd
// requires a nas_identifier with FT and parses r1_key_holder as exactly 12
// hex digits with no colons ("Invalid r1_key_holder" aborts the whole
// process). peers are the other units' key holders for FT-SAE (peersFor):
// one r0kh and one r1kh line each, with the key.
func writeFT(w func(string, any), s SSID, band, kh string, peers []ftpeer.Peer) error {
	if len(kh) != 12 || !isHex(kh) {
		return fmt.Errorf("802.11r needs the BSSID, got %q", kh)
	}
	w("mobility_domain", fmt.Sprintf("%04x", ssidMDID(s, band)))
	w("nas_identifier", kh)
	w("r1_key_holder", kh)
	w("ft_over_ds", b2i(s.FTOverDS))
	if s.Security == SecWPA2 || s.Security == SecWPA2WPA3 {
		// FT-PSK: PMK-R0/R1 generated locally from the PSK.
		w("ft_psk_generate_local", 1)
	}
	w("reassociation_deadline", ftReassocMS)
	if !s.FTSAE || s.Security != SecWPA3 && s.Security != SecWPA2WPA3 {
		return nil // no SAE AKM: the key stays out of the conf
	}
	if !validFTKey(s.FTKey) {
		return fmt.Errorf("FT-SAE without a valid key")
	}
	k := strings.ToLower(s.FTKey)
	for _, p := range peers {
		if p.Holder.Valid() != nil {
			return fmt.Errorf("FT-SAE peer %s: invalid key holder", p.BSSID)
		}
		w("r0kh", p.BSSID+" "+p.R0KHID+" "+k)
		w("r1kh", p.BSSID+" "+p.R1KHID+" "+k)
	}
	w("pmk_r1_push", 1)
	return nil
}

// ServesFTSAE reports that a SSID with FT and the controller's WPA3 fast
// roaming gets FT-SAE: only with SAE served (Options.WPA3) and FT-SAE
// enabled (Options.FTSAE: the agent's wpa3 and ft_sae).
func (a *Applier) ServesFTSAE() bool { return a.o.WPA3 && a.o.FTSAE }

// withoutFTSAE drops FT-SAE from s when it may not be served (the
// controller sent wpa3.ft.status although the agent did not claim
// radio_caps2 0x2): s keeps FT-PSK, its SAE clients join without FT, and
// the key is dropped. note is empty when s did not ask for FT-SAE.
func withoutFTSAE(s SSID) (out SSID, note string) {
	if !s.FT || !s.FTSAE {
		return s, ""
	}
	s.FTSAE, s.FTKey = false, ""
	if strings.EqualFold(strings.TrimSpace(s.Security), SecWPA2) {
		return s, "" // SAE off (withoutSAE): its note says so
	}
	return s, fmt.Sprintf("ssid %s: FT-SAE not built: off in the agent's config (ft_sae false, or wpa3 off), so SAE clients join without 802.11r", s.ID)
}
