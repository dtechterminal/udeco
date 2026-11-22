// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"fmt"
	"maps"
	"os"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mtkft"
	"github.com/dtechterminal/udeco/internal/translate"
)

// 802.11r in the radio plans (docs/deco/features/garage-ft.md). The keys
// are profile keys, so turning FT on or off rides the one restart of a
// change; the hand-back restores the vendor's profile (FT off). The
// runtime (key transfers with the Decos, neighbour lists, BSS transition
// requests) is roam.go.
//
// Each BSS takes the Decos' view of its SSID: bcmwifi.NormalizeFT with the
// same wpa3 and ft_sae keys, and bcmwifi.SSIDMDID for the mobility
// domain, so a client roams between a Deco and the Garage in one mobility
// domain. What the Garage builds per security:
//
//   - WPA2 (WPA2PSK): FT-PSK on both drivers.
//   - WPA2/WPA3 (WPA2PSKWPA3PSK): FT-PSK; FT-SAE too when served (the
//     controller's WPA3 fast roaming, a usable iapp_key, the agent's ft_sae).
//     The MT7663 adds FT-SAE with FtSupport whatever the agent wants
//     (APSecInit): without a shared key it works within the Garage only and
//     SAE clients do a full SAE at a Deco, as without 802.11r (noted).
//     The MT7603 has FtSae for it.
//   - WPA3 (WPA3PSK): only with FT-SAE served (as a Deco).
//   - Open, enterprise: none (as a Deco).

// ft2GWhy is the reason the agent's neighbour lists are off on rd.
func ft2GWhy(rd RadioDef) string {
	if rd.NoFTWhy != "" {
		return " (" + rd.NoFTWhy + ")"
	}
	return ""
}

// ftPlan sets b's 802.11r from s (its band's values) on rd. sae: the
// agent's wpa3 key.
func ftPlan(b *BSS, s bcmwifi.SSID, rd RadioDef, sae bool, note func(string, ...any)) {
	if !s.FT {
		return
	}
	v := s
	if !sae || !rd.FTSAE {
		v.FTSAE, v.FTKey = false, ""
	}
	if !sae && v.Security == translate.SecWPA2WPA3 {
		v.Security = translate.SecWPA2 // as a Deco's withoutSAE
	}
	v, ns := bcmwifi.NormalizeFT(v)
	for _, n := range ns {
		note("%s: %s", rd.Band, n)
	}
	if !v.FT {
		return
	}
	if !rd.FT {
		why := rd.NoFTWhy
		if why == "" {
			why = fmt.Sprintf("the %s driver has no 802.11r", rd.HWName)
		}
		note("%s: SSID %q: 802.11r not served: %s: clients roam with a full association", rd.Band, s.SSID, why)
		return
	}
	switch b.Auth {
	case "WPA2PSK":
	case "WPA2PSKWPA3PSK", "WPA3PSK":
		b.FTSAE = v.FTSAE
		if !v.FTSAE && rd.Band == "na" {
			note("%s: SSID %q: the driver offers FT-SAE with FT-PSK; with no WLAN key shared, SAE clients roam to the other APs with a full SAE", rd.Band, s.SSID)
		}
	default:
		return
	}
	b.FT, b.MDID = true, bcmwifi.SSIDMDID(v, rd.Band)
}

// ftKeys writes the 802.11r profile keys of rp. Nothing when no BSS has
// FT: the vendor's values stay (FT off), and a plan without FT renders
// the profile an older agent wrote.
func ftKeys(kv map[string]string, base []byte, rd RadioDef, rp RadioPlan) {
	on := false
	for _, b := range rp.BSS {
		on = on || b.FT
	}
	if !on {
		return
	}
	n := len(rd.Ifaces)
	if rd.Band == "na" {
		// the MT7663 (mtkft.ProfileKeys: byte-swapped FtMdId, the
		// 24-character R0KH-ID); PMKCachePeriod=720 is the vendor's
		slots := make([]mtkft.BSSFT, n)
		for i, b := range rp.BSS {
			if b.FT && rp.slot(i) < n {
				slots[rp.slot(i)] = mtkft.BSSFT{On: true, MDID: mtkft.MDID(b.MDID), R0KHID: b.R0KHID}
			}
		}
		m, err := mtkft.ProfileKeys(slots)
		if err != nil {
			return // ftIDs turns such a BSS's FT off: not reached
		}
		maps.Copy(kv, m)
		return
	}
	// the MT7603 (mt7603roam): FtMdId in hostapd's order, the R0KH-ID
	// left to the driver (its BSSID's 12 hex digits, as a Deco's
	// nas_identifier)
	sup, sae := make([]string, n), make([]string, n)
	for i := range sup {
		sup[i], sae[i] = "0", "0"
	}
	for i, b := range rp.BSS {
		if !b.FT || rp.slot(i) >= n {
			continue
		}
		s := rp.slot(i)
		sup[s], sae[s] = "1", b01(b.FTSAE)
		kv[fmt.Sprintf("FtMdId%d", s+1)] = fmt.Sprintf("%04x", b.MDID)
	}
	kv["FtSupport"] = strings.Join(sup, ";")
	kv["FtSae"] = strings.Join(sae, ";")
	// the PMK-R0/R1 lifetime: the vendor's 10 minutes would end an FT
	// session's keys long before a Deco's (hostapd r0_key_lifetime 12 h)
	kv["PMKCachePeriod"] = "720"
}

// ftIDs fills the R0KH-ID of each 5 GHz FT BSS of ps from its netdev's
// address (after pinning: the slot decides the netdev). A BSS whose
// address cannot be read gets no FT, with a note.
func (a *Applier) ftIDs(ps map[string]RadioPlan) []string {
	var notes []string
	for _, rd := range a.o.Layout {
		rp, ok := ps[rd.Band]
		if !ok || rd.Band != "na" {
			continue
		}
		changed := false
		bss := append([]BSS(nil), rp.BSS...)
		for i := range bss {
			if !bss[i].FT {
				continue
			}
			ifc := a.ifaceOf(rd, rp, i)
			mac, err := a.netdevMAC(ifc)
			if err != nil {
				bss[i].FT, bss[i].FTSAE, bss[i].MDID, bss[i].R0KHID = false, false, 0, ""
				notes = append(notes, fmt.Sprintf("na: SSID %q: 802.11r not served: the address of %s: %v", bss[i].SSID, ifc, err))
			} else {
				bss[i].R0KHID = mtkft.R0KHID(mac)
			}
			changed = true
		}
		if changed {
			rp.BSS = bss
			ps[rd.Band] = rp
		}
	}
	return notes
}

// netdevMAC is ifc's address (sysfs).
func (a *Applier) netdevMAC(ifc string) (mtkft.MAC, error) {
	b, err := os.ReadFile(a.dev("/sys/class/net/" + ifc + "/address"))
	if err != nil {
		return mtkft.MAC{}, err
	}
	m, err := mtkft.ParseMAC(strings.TrimSpace(string(b)))
	if err == nil && m == (mtkft.MAC{}) {
		err = fmt.Errorf("zero address")
	}
	return m, err
}
