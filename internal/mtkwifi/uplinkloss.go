// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"fmt"
	"time"
)

// Uplink loss. A U6 whose uplink goes down takes its user and guest SSIDs
// down (syswrapper.sh: state "down" -> configure_vap, stop_vap), so its
// clients roam to an AP with a path instead of staying on one without.
// The Garage keeps ONE SSID up meanwhile (the U6's isolated_wlan_on
// keeps its management VAP): the GL KVM side door joins it to reach the
// unit when its wired side is down.
//
// Each change is one restart per radio whose SSIDs change (the radio's
// profile is re-read), through the applier's lock and RestartGate like an
// Apply. Hold-down and rate limit are UplinkWatch's: isolate after
// uplinkLossAfter without carrier, restore after uplinkBackAfter with
// carrier, and never isolate again within uplinkIsoGap of a restore. While
// isolated, Verify and Tick check the isolated plan (the SSIDs that are
// down are no drift) and an Apply applies the controller's plan isolated;
// last-good keeps the controller's plan.

const (
	uplinkLossAfter = 15 * time.Second
	uplinkBackAfter = 30 * time.Second
	uplinkIsoGap    = 5 * time.Minute
)

// UplinkWatch turns carrier readings into the isolation decision.
type UplinkWatch struct {
	isolated bool
	since    time.Time // the carrier state last changed
	carrier  bool
	seen     bool
	restored time.Time // the last restore
}

// Observe takes one carrier reading and returns whether the SSIDs should
// be isolated now.
func (w *UplinkWatch) Observe(carrier bool, now time.Time) bool {
	if !w.seen || carrier != w.carrier {
		w.seen, w.carrier, w.since = true, carrier, now
	}
	held := now.Sub(w.since)
	switch {
	case !w.isolated && !carrier && held >= uplinkLossAfter &&
		(w.restored.IsZero() || now.Sub(w.restored) >= uplinkIsoGap):
		w.isolated = true
	case w.isolated && carrier && held >= uplinkBackAfter:
		w.isolated, w.restored = false, now
	}
	return w.isolated
}

// isolatedPlans is want with only the management SSID left on the radios
// that serve it (the others off): the SSID named keep, else the first one
// on the LAN (no VLAN) of the first radio. nil when no such SSID is
// served: nothing is taken down then.
func isolatedPlans(want map[string]RadioPlan, keep string) map[string]RadioPlan {
	id := ""
	for _, band := range []string{"ng", "na"} {
		for _, b := range want[band].BSS {
			if id == "" && (keep != "" && b.SSID == keep || keep == "" && b.VLAN == 0 && !b.Guest) {
				id = b.ID
			}
		}
	}
	if id == "" {
		return nil
	}
	out := map[string]RadioPlan{}
	for band, rp := range want {
		c := rp
		c.BSS, c.Slots = nil, nil // the kept SSID in slot 0
		for _, b := range rp.BSS {
			if b.ID == id {
				c.BSS = append(c.BSS, b)
			}
		}
		if len(c.BSS) == 0 {
			c.On, c.Channel = false, 0
		}
		out[band] = c
	}
	return out
}

// effective is what the radios serve for the controller's plan want: want
// itself, or isolated while the uplink is down.
func (a *Applier) effective(want map[string]RadioPlan) map[string]RadioPlan {
	if !a.uplinkDown {
		return want
	}
	if iso := isolatedPlans(want, a.o.KeepSSID); iso != nil {
		return iso
	}
	return want
}

// SetUplinkDown isolates the SSIDs (down) or brings them all back. With
// nothing applied yet it only records the state for the next Apply.
func (a *Applier) SetUplinkDown(ctx context.Context, down bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.uplinkDown = down
	if a.live == nil || a.want == nil || a.o.DryRun {
		return nil
	}
	target := a.effective(a.want)
	if plansHash(target) == plansHash(a.live) {
		if down && isolatedPlans(a.want, a.o.KeepSSID) == nil {
			a.o.Logf("mtkwifi: uplink down: no management SSID (%q) is served: every SSID stays up", a.o.KeepSSID)
		}
		return nil
	}
	defer a.changingRadios()()
	what := "uplink down: every SSID but the management one goes down"
	if !down {
		what = "uplink back: every SSID comes back"
	}
	a.o.Logf("mtkwifi: %s", what)
	err := a.applyPlans(ctx, target, a.live)
	if err == nil {
		err = a.waitLive(ctx, target)
	}
	if err != nil {
		a.live = nil // not known: the next Plan restarts what differs
		return fmt.Errorf("%s: %w", what, err)
	}
	a.live = target
	a.flushLive(ctx)
	return nil
}
