// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Roaming Assistant primitive (docs/deco/features/roaming-assistant.md).
//
// A UAP implements the controller's Roaming Assistant (system_cfg
// wireless.N.btm_disassoc.status/threshold) in its driver: btm_disassoc 1
// and btm_dis_thld <dBm>. The X20's Broadcom driver has nothing like it,
// so the agent watches its stations' signal and, for one below the
// threshold, asks hostapd 2.9 for an 802.11v BSS Transition Management
// request with the Disassociation Imminent bit, the candidate BSSes, and a
// disassociation timer (hostapd disassociates the station when the timer
// runs out and it is still there):
//
//	bss_tm_req <sta> disassoc_imminent=1 disassoc_timer=<TBTT> pref=1 abridged=1 neighbor=<bssid>,<info>,<opclass>,<chan>,<phy> ...
//
// Two guards keep it from becoming a bare kick: a station whose driver
// record (`wl sta_info`, "wnm" capability line) does not list
// BSS-Transition is never sent one (ErrNoBTM), and a request needs at
// least one candidate (ErrNoCandidate). Checked against the binary on .205:
// hostapd 2.9 has bss_tm_req with disassoc_timer=, disassoc_imminent=1,
// pref=, abridged= and neighbor= (strings), and set_disassoc_timer.

// Neighbor is a BSS a station may be asked to move to.
type Neighbor struct {
	BSSID   string
	Band    string // "ng" or "na"
	Channel int    // primary channel
}

// RoamRequest asks station MAC on Vif (a BSS the agent serves) to move to
// one of Candidates; DisassocTBTT > 0 adds the disassociation timer (in
// beacon intervals) after which hostapd disassociates it.
type RoamRequest struct {
	Vif, MAC     string
	Candidates   []Neighbor
	DisassocTBTT int
}

var (
	// ErrNoBTM: the station did not advertise BSS transition support; it
	// is left alone (a request would be ignored and the timer would only
	// disconnect it).
	ErrNoBTM = errors.New("bcmwifi: station does not support BSS transition management")
	// ErrNoCandidate: no usable candidate BSS was given.
	ErrNoCandidate = errors.New("bcmwifi: no candidate BSS to move to")
)

// maxRoamCandidates bounds the neighbour list (hostapd's buffer is 2 KB;
// each entry is 15 bytes, the request frame must stay small).
const maxRoamCandidates = 6

// maxDisassocTBTT is the largest timer accepted (the field is 16 bits;
// hostapd itself takes any number). About 100 s at 102.4 ms beacons.
const maxDisassocTBTT = 1000

// RoamAssist sends one Roaming Assistant request (see above). It returns
// ErrNotOwned when the agent serves no BSS, ErrNoBTM for a station without
// BSS transition support, ErrNoCandidate when no candidate is usable, and
// an error when hostapd refuses the request.
func (a *Applier) RoamAssist(ctx context.Context, r RoamRequest) error {
	m := normMAC(r.MAC)
	if m == "" {
		return fmt.Errorf("bcmwifi: roam: bad MAC %q", r.MAC)
	}
	if r.DisassocTBTT < 0 || r.DisassocTBTT > maxDisassocTBTT {
		return fmt.Errorf("bcmwifi: roam: disassociation timer %d out of range 0..%d", r.DisassocTBTT, maxDisassocTBTT)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ours := a.ourVifs()
	if len(ours) == 0 {
		return ErrNotOwned
	}
	if !contains(ours, r.Vif) {
		return fmt.Errorf("bcmwifi: roam: %q is not a BSS the agent serves", r.Vif)
	}
	own, err := a.bssid(ctx, r.Vif)
	if err != nil {
		return fmt.Errorf("bcmwifi: roam: %w", err)
	}
	var nbs []string
	seen := map[string]bool{own: true}
	for _, c := range r.Candidates {
		b, band := normMAC(c.BSSID), normBand(c.Band)
		if b == "" || band == "" || c.Channel <= 0 || c.Channel > 196 || seen[b] {
			continue
		}
		seen[b] = true
		info, opClass, phy := neighborInfo(band, c.Channel)
		if opClass == 0 {
			continue // a 5 GHz channel with no operating class here
		}
		nbs = append(nbs, fmt.Sprintf("neighbor=%s,%d,%d,%d,%d", b, info, opClass, c.Channel, phy))
		if len(nbs) == maxRoamCandidates {
			break
		}
	}
	if len(nbs) == 0 {
		return ErrNoCandidate
	}
	out, err := a.wlGet(ctx, r.Vif, "sta_info", m)
	if err != nil {
		return fmt.Errorf("bcmwifi: roam: %w", err)
	}
	if !staBTM(out) {
		return ErrNoBTM
	}
	args := []string{"bss_tm_req", m}
	if r.DisassocTBTT > 0 {
		args = append(args, "disassoc_imminent=1", "disassoc_timer="+strconv.Itoa(r.DisassocTBTT))
	}
	args = append(args, "pref=1", "abridged=1")
	args = append(args, nbs...)
	if err := a.hostapdCLI(ctx, r.Vif, args...); err != nil {
		return fmt.Errorf("bcmwifi: roam %s: %w", m, err)
	}
	return nil
}

// staBTM reads a station's BSS transition support from `wl sta_info`: the
// line after "wnm" is the driver's WNM capability word with names, e.g.
// "0x21:  BSS-Transition  WNM-Sleep-Mode" or "0x0:" (bit 0x1 is BSS
// transition; fixtures from .205 in internal/wl/testdata). No such line
// means unknown, which counts as no.
func staBTM(out string) bool {
	lines := strings.Split(out, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != "wnm" || i+1 >= len(lines) {
			continue
		}
		f := strings.Fields(lines[i+1])
		if len(f) == 0 {
			return false
		}
		v, err := strconv.ParseUint(strings.TrimSuffix(f[0], ":"), 0, 32)
		if err != nil {
			return false
		}
		return v&0x1 != 0
	}
	return false
}
