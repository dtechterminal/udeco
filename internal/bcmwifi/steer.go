// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"

	"github.com/dtechterminal/udeco/internal/rf"
)

// Band steering primitive. The X20 has no Broadcom steering daemon (no
// bsd/wbd), and the policy (who, when, where) belongs to the agent. This
// sends one 802.11v BSS Transition Management request through hostapd 2.9
// (`hostapd_cli bss_tm_req`, present on the X20; hostapd has
// ieee802_11_parse_candidate_list), naming one of this AP's own BSSes as
// the only candidate:
//
//	bss_tm_req <sta> pref=1 abridged=1 neighbor=<bssid>,<info>,<opclass>,<channel>,<phy>
//
// The station decides; one that ignores BTM stays put (the agent may Kick
// it afterwards). Assumptions, untested on the X20: hostapd parses the
// neighbor fields as decimal (upstream 2.9 does), and stations act on a
// request from a BSS whose SSID has bss_transition on (SSID.BSSTransition).

// neighborInfo returns the BSSID information, 20 MHz operating class
// (rf.OpClass: 0 for a channel no class has) and PHY type of a candidate
// on band/channel, as the 802.11k list in internals.md uses them (0x08af,
// +0x1000 VHT on 5 GHz; PHY 7 HT, 9 VHT).
func neighborInfo(band string, ch int) (info, opClass, phy int) {
	if band == rf.Band2G {
		return 0x08af, rf.OpClass(band, ch), 7
	}
	return 0x18af, rf.OpClass(band, ch), 9
}

// SteerToBand asks station mac, associated on vif, to move to targetBSSID,
// which must be another BSS the agent serves (normally the same SSID on the
// other band). It returns ErrNotOwned when the agent serves no BSS, and an
// error when hostapd refuses the request (station not associated, BTM not
// supported).
func (a *Applier) SteerToBand(ctx context.Context, vif, mac, targetBSSID string) error {
	m, t := normMAC(mac), normMAC(targetBSSID)
	if m == "" || t == "" {
		return fmt.Errorf("bcmwifi: steer: bad MAC %q or BSSID %q", mac, targetBSSID)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ours := a.ourVifs()
	if len(ours) == 0 {
		return ErrNotOwned
	}
	if !contains(ours, vif) {
		return fmt.Errorf("bcmwifi: steer: %q is not a BSS the agent serves", vif)
	}
	target := ""
	for _, v := range ours {
		if b, err := a.bssid(ctx, v); err == nil && b == t {
			target = v
			break
		}
	}
	if target == "" {
		return fmt.Errorf("bcmwifi: steer: %s is not one of this AP's BSSes", t)
	}
	if target == vif {
		return fmt.Errorf("bcmwifi: steer: %s is the station's own BSS", t)
	}
	prim, band := target[:3], ""
	for b, p := range bandPrimary {
		if p == prim {
			band = b
		}
	}
	out, err := a.wlGet(ctx, prim, "chanspec")
	if err != nil {
		return fmt.Errorf("bcmwifi: steer: %w", err)
	}
	cs, err := parseChanspec(out)
	if err != nil {
		return fmt.Errorf("bcmwifi: steer: %s: %w", prim, err)
	}
	info, opClass, phy := neighborInfo(band, cs.Ctrl)
	if opClass == 0 {
		return fmt.Errorf("bcmwifi: steer: %s: no operating class for %s channel %d", prim, band, cs.Ctrl)
	}
	nb := fmt.Sprintf("neighbor=%s,%d,%d,%d,%d", t, info, opClass, cs.Ctrl, phy)
	if err := a.hostapdCLI(ctx, vif, "bss_tm_req", m, "pref=1", "abridged=1", nb); err != nil {
		return fmt.Errorf("bcmwifi: steer %s to %s: %w", m, t, err)
	}
	return nil
}
