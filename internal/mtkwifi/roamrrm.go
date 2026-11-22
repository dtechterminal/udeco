// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/dtechterminal/udeco/internal/bcmwifi"
	"github.com/dtechterminal/udeco/internal/mtkft"
	"github.com/dtechterminal/udeco/internal/rf"
)

// 802.11v for the agent's band steering and Roaming Assistant (garage_ft;
// docs/deco/features/garage-ft.md). The policy is the agent's, as on the
// Deco (bcmwifi steer.go, roaming.go); this sends one BSS Transition
// Management request:
//
//   - 2.4 GHz (the rebuilt mt7603roam only): `iwpriv raN set
//     BtmReq=<sta>,<bssid>,<channel>[,<timer>]`, one candidate. The driver
//     refuses (EINVAL) a station that did not claim BSS transition support,
//     which maps to bcmwifi.ErrNoBTM.
//   - 5 GHz: OID 0x0928 (mtkft.BTMReq), the whole candidate list. The
//     driver does not check the station's BSS transition support on this
//     path and arms its own countdown with "disassociation imminent"
//     (SendBTMReq, verified; that it disconnects is inferred). A station
//     without BTM support would then be dropped, so on 5 GHz the request
//     never sets that bit: candidates only (preferred list, abridged), and
//     the station decides.
//
// 802.11k: both drivers answer a neighbour report request from their own
// scan table when the agent gives them no list (verified for the MT7663,
// RRM_EnqueueNeighborRep; the MT7603 module the same, when its NrAdd list
// is empty). The agent leaves that in place: no lists are written and
// NRByDaemon stays off, so a request is never left unanswered.

var errBTMOff = errors.New("mtkwifi: 802.11v (BSS transition) is off on this SSID")

// btmBSS finds the served BSS on vif (a.mu held).
func (a *Applier) btmBSS(vif string) (roamBSS, error) {
	if a.live == nil || a.roam == nil {
		return roamBSS{}, bcmwifi.ErrNotOwned
	}
	if !a.ServesRoaming() {
		return roamBSS{}, errors.New("mtkwifi: 802.11v requests need garage_ft")
	}
	a.roam.mu.Lock()
	b, ok := a.roam.bssByIfname(vif)
	a.roam.mu.Unlock()
	if !ok {
		return roamBSS{}, fmt.Errorf("mtkwifi: %q is not a BSS the agent serves with garage_ft", vif)
	}
	if !b.BTM {
		return b, errBTMOff
	}
	return b, nil
}

// ownBSSIDs is every BSSID this unit serves (a.mu held).
func (a *Applier) ownBSSIDs() map[mtkft.MAC]roamBSS {
	out := map[mtkft.MAC]roamBSS{}
	a.roam.mu.Lock()
	defer a.roam.mu.Unlock()
	for _, b := range a.roam.bss {
		out[b.BSSID] = b
	}
	return out
}

// SteerToBand asks station mac on vif to move to targetBSSID, another BSS
// of this unit (normally the same SSID on the other band).
func (a *Applier) SteerToBand(ctx context.Context, vif, mac, targetBSSID string) error {
	sta, err := mtkft.ParseMAC(mac)
	if err != nil {
		return fmt.Errorf("mtkwifi: steer: bad MAC %q", mac)
	}
	t, err := mtkft.ParseMAC(targetBSSID)
	if err != nil {
		return fmt.Errorf("mtkwifi: steer: bad BSSID %q", targetBSSID)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := a.btmBSS(vif)
	if err != nil {
		return err
	}
	tb, ok := a.ownBSSIDs()[t]
	if !ok {
		return fmt.Errorf("mtkwifi: steer: %s is not one of this AP's BSSes", t)
	}
	if tb.Ifname == vif {
		return fmt.Errorf("mtkwifi: steer: %s is already on %s", sta, vif)
	}
	ch := a.channelOf(ctx, tb.Ifname)
	if ch <= 0 {
		return fmt.Errorf("mtkwifi: steer: the channel of %s is unknown", tb.Ifname)
	}
	return a.sendBTM(ctx, b, sta, []bcmwifi.Neighbor{{BSSID: t.String(), Band: tb.Band, Channel: ch}}, 0, true)
}

// RoamAssist sends one Roaming Assistant request: station r.MAC on r.Vif
// to one of r.Candidates (never this unit's own BSSes). On 5 GHz the
// disassociation timer is not sent (see above).
func (a *Applier) RoamAssist(ctx context.Context, r bcmwifi.RoamRequest) error {
	sta, err := mtkft.ParseMAC(r.MAC)
	if err != nil {
		return fmt.Errorf("mtkwifi: roam: bad MAC %q", r.MAC)
	}
	if r.DisassocTBTT < 0 || r.DisassocTBTT > 1000 {
		return fmt.Errorf("mtkwifi: roam: disassociation timer %d out of range 0..1000", r.DisassocTBTT)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	b, err := a.btmBSS(r.Vif)
	if err != nil {
		return err
	}
	own := a.ownBSSIDs()
	var cs []bcmwifi.Neighbor
	seen := map[mtkft.MAC]bool{}
	for _, c := range r.Candidates {
		m, err := mtkft.ParseMAC(c.BSSID)
		band := rf.Norm(c.Band)
		if err != nil || band == "" || c.Channel <= 0 || c.Channel > 196 || seen[m] {
			continue
		}
		if _, mine := own[m]; mine {
			continue // a client sent to this unit's other band only comes back (as on the Deco)
		}
		seen[m] = true
		cs = append(cs, c)
		if len(cs) == 6 {
			break
		}
	}
	if len(cs) == 0 {
		return bcmwifi.ErrNoCandidate
	}
	return a.sendBTM(ctx, b, sta, cs, r.DisassocTBTT, false)
}

// sendBTM sends the request on b's driver (a.mu held).
func (a *Applier) sendBTM(ctx context.Context, b roamBSS, sta mtkft.MAC, cs []bcmwifi.Neighbor, timer int, sameUnit bool) error {
	if b.Band == "ng" {
		c := cs[0] // the MT7603 module takes one candidate
		arg := fmt.Sprintf("BtmReq=%s,%s,%d", sta, strings.ToLower(c.BSSID), c.Channel)
		if timer > 0 {
			arg += fmt.Sprintf(",%d", timer)
		}
		if err := a.run(ctx, "iwpriv", b.Ifname, "set", arg); err != nil {
			if strings.Contains(err.Error(), "nvalid argument") {
				return bcmwifi.ErrNoBTM // or not on this BSS (any more)
			}
			return err
		}
		a.roam.mu.Lock()
		a.roam.count("btm-sent-ng")
		a.roam.mu.Unlock()
		return nil
	}
	req := mtkft.BTMRequest{Mode: mtkft.BTMAbridged, Validity: 200}
	for i, c := range cs {
		m, _ := mtkft.ParseMAC(c.BSSID)
		band := rf.Norm(c.Band)
		info := uint32(mtkft.BSSIDReachable | mtkft.BSSIDSecurity | mtkft.BSSIDKeyScope | mtkft.BSSIDHighThroughpt)
		phy := byte(7)
		if band == rf.Band5G {
			info |= mtkft.BSSIDVHT
			phy = 9
		}
		if sameUnit || a.sameDomain(b, m) {
			info |= mtkft.BSSIDMobilityDom
		}
		req.Candidates = append(req.Candidates, mtkft.NeighborReport{BSSID: m, Info: info,
			OpClass: byte(rf.OpClass(band, c.Channel)), Channel: byte(c.Channel), PHYType: phy, Preference: byte(255 - i)})
	}
	q, err := mtkft.BTMReq(sta, req)
	if err != nil {
		return err
	}
	ran, err := a.roam.drv(func() error { return a.roam.oid(b.Ifname, q) })
	if !ran {
		return errors.New("mtkwifi: a radio restart is settling: no BTM request now")
	}
	if err != nil {
		return fmt.Errorf("mtkwifi: BTM request on %s: %w", b.Ifname, err)
	}
	a.roam.mu.Lock()
	a.roam.count("btm-sent-na")
	a.roam.mu.Unlock()
	return nil
}

// sameDomain: m is a Deco key holder in b's mobility domain.
func (a *Applier) sameDomain(b roamBSS, m mtkft.MAC) bool {
	a.roam.mu.Lock()
	defer a.roam.mu.Unlock()
	for _, p := range a.roam.peers {
		if bs, _, err := peerMACs(p); err == nil && bs == m && p.Holder.MDID == b.MDID {
			return b.FT
		}
	}
	return false
}

// onRRMEvent takes the MT7663's BTM responses and queries (flags 0x093a,
// 0x0929) and neighbour report requests (0x094D: only with NRByDaemon,
// which the agent leaves off; counted). The outcome of a request is the
// station's next association, which the agent sees anyway; these are
// counted for RoamStats.
func (r *roam) onRRMEvent(ifc string, flags uint16, data []byte) {
	ev, err := mtkft.ParseEvent(flags, data)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.count("rrm-malformed")
		return
	}
	switch e := ev.(type) {
	case *mtkft.BTMEvent:
		switch {
		case e.Flags == mtkft.EvBTMQuery:
			r.count("btm-query")
		case e.Timeout:
			r.count("btm-timeout")
		case e.Status == 0:
			r.count("btm-accept")
		default:
			r.count(fmt.Sprintf("btm-reject-%d", e.Status))
		}
	case *mtkft.NeighborRequest:
		r.count("nr-request")
	}
}
