// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
)

// TWT (802.11ax Target Wake Time). A real UniFi U6 Pro sets
// `cfg80211tool <vap> twt_responder 3` on every VAP whatever the controller
// sends (docs/reference/u6pro/config-apply/sysinit/wireless.conf); TP-Link's
// tplink_brcm.sh runs `wl twt 0` after wlconf, and the Bedroom Deco's wl1
// read `twt enab` 0 (2026-11-20). The agent turns it on (Options.NoTWT keeps
// TP-Link's 0) with the explicit `wl -i <radio> twt enab <0|1>` form: the
// driver documents `wl twt enab [0|1]` ("query or enable/disable TWT
// feature"), and `wl twt` with no argument prints the same enable state
// (Bedroom Deco, 2026-11-20). What TP-Link's bare `wl twt 0` does is not
// verified (an alias of `twt enab 0`, or an unknown subcommand); the
// hand-back therefore restores the state the baseline read, not that line.
//
// The driver refuses `twt enab` while the radio is up ("wl: Not down") and
// takes it after `wl down`; `wl up` brings the BSSes back with hostapd
// running, as radioDownSteps does. A radio restart drops every client, so
// TWT never causes one by itself: it is set inside a down/up the plan
// makes anyway (the PHY change's radioProfile, a full reconcile's
// dwds/rrm cycle, or Tick's dwds repair). A unit whose radio reads
// otherwise (an agent upgraded under its running hostapd) converges at its
// next such restart, at the latest at the next boot's takeover; until then
// the plan notes and Tick's log say so.

// twtStep sets the radio's TWT enable state (radio down only). Optional: a
// driver without the iovar keeps the radio going.
func twtStep(primary string, on bool) Step {
	desc := "TWT off"
	if on {
		desc = "TWT on"
	}
	return optStep(desc, "wl", "-i", primary, "twt", "enab", itoa(b2i(on)))
}

// readTWT reads the radio's TWT enable state: -1 when unreadable.
func (a *Applier) readTWT(ctx context.Context, primary string) int {
	out, err := a.wlGet(ctx, primary, "twt", "enab")
	if err != nil {
		return -1
	}
	n, err := parseIntOut(out)
	if err != nil || n < 0 || n > 1 {
		return -1
	}
	return n
}

// twtStatus is a radio's TWT line in the plan notes and Tick's log: live is
// the state read before the plan (-1 unreadable), set whether the plan
// writes it inside a radio down/up.
func twtStatus(primary string, live int, want, set bool) string {
	w := b2i(want)
	switch {
	case set && live < 0:
		return fmt.Sprintf("TWT state unreadable (wl -i %s twt enab); twt enab %d tried inside this plan's radio down/up", primary, w)
	case set && live != w:
		return fmt.Sprintf("TWT enab %d -> %d inside this plan's radio down/up", live, w)
	case live < 0:
		return fmt.Sprintf("TWT state unreadable (wl -i %s twt enab): left as it is", primary)
	case live == w && want:
		return "TWT on (twt enab 1)"
	case live == w:
		return "TWT off (twt enab 0, config twt false)"
	}
	return fmt.Sprintf("TWT enab %d, config wants %d: set at the next radio down/up (a channel, country or hostapd change, a dwds repair, the next boot); TWT alone never restarts the radio", live, w)
}

// logTWT logs each radio's TWT line when it differs from the one Tick
// logged last: the first tick, a state waiting for a radio restart, the
// restart that set it.
func (a *Applier) logTWT(p Plan) {
	for _, band := range sortedKeys(p.twt) {
		line := p.twt[band]
		if a.twtSeen[band] == line {
			continue
		}
		if a.twtSeen == nil {
			a.twtSeen = map[string]string{}
		}
		a.twtSeen[band] = line
		a.o.Logf("bcmwifi: tick: %s", line)
	}
}
