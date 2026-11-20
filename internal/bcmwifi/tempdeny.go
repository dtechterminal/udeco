// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Short per-BSS bans (the agent's minimum RSSI kick and "restrict to
// 5 GHz": cmd/udeco-ap minrssi.go, no2ghz.go).
//
// A ban puts one station into one vif's driver MAC filter in deny mode
// and deauthenticates it from that BSS only. The driver filter is what
// keeps it out: with driver SME the association never passes hostapd's
// ACL, and with probresp_mac_filter on (TP-Link's setting, read on every
// unit) a listed station gets no probe response either, so it does not
// even see the BSS. The ban lives only in this Applier: the stored driver
// state, hostapd's ACL files and the controller's block list are not
// touched, and Plan, Tick and the block-list refresh add the live bans to
// the vif's filter, so none of them reports or undoes it. The agent lifts
// each ban when it ends; one it never lifted (the agent stopped) lapses
// tempDenyGrace after its end, and Tick then takes it out of the filter.
// A hand-back to TP-Link forgets them all (the baseline restores TP-Link's
// filters).
//
// An allow-list SSID is refused (ErrAllowList): its driver filter is in
// allow mode, where a listed station is admitted, not denied.

// ErrAllowList: the BSS carries an allow-list SSID; no ban is possible.
var ErrAllowList = errors.New("bcmwifi: the BSS has an allow list: no per-station ban")

// tempDenyGrace is how long after its end a ban that was never lifted is
// still kept.
const tempDenyGrace = 2 * time.Minute

// TempDeny bans mac from vif until until (a zero until lifts the ban). It
// returns ErrNotOwned when the agent serves no BSS and ErrAllowList for an
// allow-list SSID.
func (a *Applier) TempDeny(ctx context.Context, vif, mac string, until time.Time) error {
	m := normMAC(mac)
	if m == "" {
		return fmt.Errorf("bcmwifi: ban: bad MAC %q", mac)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	ours := a.ourVifs()
	if len(ours) == 0 {
		return ErrNotOwned
	}
	if !contains(ours, vif) {
		return fmt.Errorf("bcmwifi: ban: %q is not a BSS the agent serves", vif)
	}
	d := a.current()
	if d == nil {
		return ErrNotOwned
	}
	var u *vifAssign
	maxSta := defaultMaxSta
	for _, rl := range a.layout(*d).Radios {
		for i := range rl.Used {
			if rl.Used[i].Vif == vif {
				u = &rl.Used[i]
				if rl.Radio.MaxClients > 0 && rl.Radio.MaxClients < maxSta {
					maxSta = rl.Radio.MaxClients
				}
			}
		}
	}
	if u == nil {
		return fmt.Errorf("bcmwifi: ban: %q carries no SSID", vif)
	}
	bssid, err := a.bssid(ctx, vif)
	if err != nil {
		return fmt.Errorf("bcmwifi: ban: %w", err)
	}
	dv := driverFor(*u, bssid, maxSta, a.loadBlocked(), a.o.MinRates)
	if dv.Allow {
		return ErrAllowList
	}
	if a.tempDeny == nil {
		a.tempDeny = map[string]map[string]time.Time{}
	}
	if until.IsZero() {
		delete(a.tempDeny[vif], m)
	} else {
		if a.tempDeny[vif] == nil {
			a.tempDeny[vif] = map[string]time.Time{}
		}
		a.tempDeny[vif][m] = until
	}
	live := a.withTempDeny(dv)
	st := macSteps(vif, live.Macmode, live.Maclist)
	if a.o.DryRun {
		a.logPlan("dry-run ban "+m+" on "+vif, Plan{Steps: st})
		return nil
	}
	if err := a.execute(ctx, st); err != nil {
		return fmt.Errorf("bcmwifi: ban %s on %s: %w", m, vif, err)
	}
	if !until.IsZero() {
		if err := a.hostapdCLI(ctx, vif, "deauthenticate", m); err != nil {
			a.o.Logf("bcmwifi: ban %s on %s: %v", m, vif, err)
		}
	}
	return nil
}

// withTempDeny is d with the live bans of its vif added to the driver MAC
// filter (deny mode). Allow-list vifs are returned as they are.
func (a *Applier) withTempDeny(d vifDriver) vifDriver {
	if d.Allow || len(a.tempDeny[d.Vif]) == 0 {
		return d
	}
	now := a.now()
	set := map[string]bool{}
	for _, m := range d.Maclist {
		set[m] = true
	}
	n := 0
	for m, until := range a.tempDeny[d.Vif] {
		if now.Sub(until) > tempDenyGrace {
			delete(a.tempDeny[d.Vif], m) // never lifted: lapsed
			continue
		}
		if !set[m] {
			set[m] = true
			n++
		}
	}
	if n == 0 {
		return d
	}
	list := make([]string, 0, len(set))
	for m := range set {
		list = append(list, m)
	}
	sort.Strings(list)
	d.Macmode, d.Maclist = 1, list
	return d
}
