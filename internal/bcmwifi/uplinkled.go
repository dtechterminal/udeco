// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"strings"
)

// The uplink-loss LED (docs/deco/features/uplink-loss.md). A U6 whose
// uplink is gone shows a fast blink. The Deco's leds daemon (actions.go
// LED) has TP-Link's own "lost the uplink" signal in its conn controller,
// as read with `ubus call leds status {"verbose":true}` after each call on
// the Hallway X20 (2026-11-20):
//
//   - conn "online":  event [1,0], green, steady;
//   - conn "offline": event [1,1], red, steady (on 4000 ms, off 0);
//   - conn "ap-lost": event [1,2], red, blink (747 ms on, 463 ms off).
//
// The hold (ssidhold.go) sets "ap-lost", the blink being the closest to the
// U6; lifting it sets "online". The "off" event (LED off) has the higher
// priority, so with the LED off conn changes underneath and the LED stays
// dark (nothing here clears "off"); locate (zigbee "identifying") blinks
// green over conn and leaves it as it was. LED on during the hold keeps
// "ap-lost" (actions.go). The hand-back and the agent's stop (ReleaseLED)
// put "online" back. A failed call is logged, never returned: the LED never
// stands in the way of the SSIDs.

const (
	connStateOnline = "online"
	connStateLost   = "ap-lost"
)

// connCall is the leds daemon call for a conn state.
func connCall(state string) []string {
	return []string{"call", "leds", "conn", `{"state":"` + state + `"}`}
}

// setConn sets the conn state (a.mu held). connRed records that the LED may
// show the red blink: it is set before "ap-lost" is tried and cleared only
// by an "online" that went through.
func (a *Applier) setConn(ctx context.Context, state string) {
	c := connCall(state)
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: ubus %s", strings.Join(c, " "))
		return
	}
	if state != connStateOnline {
		a.connRed = true
	}
	if err := a.run(ctx, append([]string{"ubus"}, c...)...); err != nil {
		a.o.Logf("bcmwifi: LED conn %s (uplink loss): %v", state, err)
		return
	}
	if state == connStateOnline {
		a.connRed = false
	}
}

// ReleaseLED puts the conn state back to "online" when the uplink-loss
// blink may be showing (the agent stops: nothing would clear it). The hold
// itself, and the SSIDs, stay as they are.
func (a *Applier) ReleaseLED(ctx context.Context) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.connRed {
		a.setConn(ctx, connStateOnline)
	}
}
