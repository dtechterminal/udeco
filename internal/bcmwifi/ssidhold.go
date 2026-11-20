// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
)

// The uplink-loss hold (cmd/udeco-ap uplink.go; docs/deco/features/
// uplink-loss.md). A U6 takes its user and guest SSIDs down while its wired
// uplink is gone, so clients roam to an AP that still reaches the network
// instead of sitting on one that does not.
//
// SSIDsDown(true) takes every BSS the agent serves down with `wl bss down`:
// no radio restart, hostapd keeps running and the vifs stay in their
// bridges. While the hold lasts, Plan (and so Tick and every apply) leaves
// them down instead of raising them, takes one that came up down again
// without reporting it as foreign, and Verify wants them down. SSIDsDown
// (false) raises them. The LED follows once the SSIDs have changed: TP-Link's
// conn "ap-lost" red blink while held, "online" when lifted (uplinkled.go).
// The hold lives only in this Applier: a new agent process starts without
// it, and a hand-back to TP-Link forgets it (the baseline's own BSS states
// are restored, and conn goes back to "online").

// SSIDsDown sets or lifts the hold. It returns ErrNotOwned when the agent
// serves no BSS.
func (a *Applier) SSIDsDown(ctx context.Context, down bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	d := a.current()
	if d == nil || len(a.ourVifs()) == 0 {
		return ErrNotOwned
	}
	// The hold changes only with the change itself: on a failure it stays
	// as it was, so Plan and Tick do not keep the SSIDs down (or up) for a
	// change the watcher will try again (Tick puts a half-done change
	// back).
	prev := a.ssidsDown
	a.ssidsDown = down
	var st []Step
	for _, rl := range a.layout(*d).Radios {
		if !a.netdevExists(rl.Primary) {
			continue
		}
		for _, u := range rl.Used {
			if down {
				st = append(st, onVif(u.Vif, cmdStep("uplink lost: lower "+u.Vif, "wl", "-i", u.Vif, "bss", "down")))
			} else {
				st = append(st, cmdStep("uplink back: raise "+u.Vif, "wl", "-i", u.Vif, "bss", "up"))
			}
		}
	}
	led := map[bool]string{true: connStateLost, false: connStateOnline}[down]
	if a.o.DryRun {
		a.logPlan(fmt.Sprintf("dry-run SSIDs down=%t", down), Plan{Steps: st})
		a.setConn(ctx, led)
		return nil
	}
	if err := a.executeAll(ctx, st); err != nil {
		a.ssidsDown = prev
		return fmt.Errorf("bcmwifi: SSIDs down=%t: %w", down, err)
	}
	// the LED follows the SSIDs, never the other way round (uplinkled.go)
	a.setConn(ctx, led)
	return nil
}

// SSIDsHeld reports whether the hold is on.
func (a *Applier) SSIDsHeld() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ssidsDown
}
