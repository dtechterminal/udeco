// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"context"
	"time"
)

// monoSince is the default Options.mono: time since the process's first
// Applier, from the monotonic clock (time.Since uses it; wall-clock steps
// do not move it).
func monoSince(start time.Time) func() time.Duration {
	return func() time.Duration { return time.Since(start) }
}

// Radio restarts and driver reads. The MT7603/MT7663 drivers are probed
// (iwconfig, iwpriv show ..., get_site_survey) by the collector on its own
// schedule: every inform, the 1 s live view and the minute's home listen.
// A 55-minute hang of the unit on 2026-11-19 followed such probes while a
// radio was being restarted, so the collector keeps away from the driver
// while the applier changes the radios and for a settle time after the
// last radio restart:
//
//   - Apply and Rollback hold the gate's write side for their whole run.
//     They wait for a driver read already under way to finish; a read that
//     would start meanwhile does not wait, it is skipped.
//   - Each radio restart (applyRadio, restoreBaseline) closes the gate for
//     Settle (20 s) from its end, measured on the monotonic clock: the
//     agent's clock keeping steps the wall clock (clock.go), and a step
//     must neither end the settle time early nor stretch it.
//   - The applier's own routine reads keep off the driver while it settles
//     too: Tick and Verify skip their iwconfig SSID reads (sysfs only), and
//     an unchanged station ACL is not written again (SetBlocked).
//   - A skipped read gives the collector's last reading (or none): the
//     inform loop, the live view and the home listen never wait on an
//     apply.

// defaultSettle: driver reads stay off this long after a radio restart.
const defaultSettle = 20 * time.Second

// RestartGate is what the collector needs of the applier (*Applier): may
// a driver read run now. It never blocks. ok false: skip the read (a
// radio restart is under way or just ended); ok true: run it, then call
// done.
type RestartGate interface {
	DriverRead() (done func(), ok bool)
}

var _ RestartGate = (*Applier)(nil)

// DriverRead implements RestartGate.
func (a *Applier) DriverRead() (func(), bool) {
	if a.settling() || !a.gate.TryRLock() {
		return nil, false
	}
	if a.settling() { // a restart ended between the two checks
		a.gate.RUnlock()
		return nil, false
	}
	return a.gate.RUnlock, true
}

// settling: a radio restart's settle time is not over (monotonic clock).
func (a *Applier) settling() bool { return int64(a.o.mono()) < a.quietUntil.Load() }

// changingRadios closes the gate for an Apply or Rollback (a.mu held):
// driver reads under way finish first, new ones are skipped until the
// returned func runs.
func (a *Applier) changingRadios() func() {
	a.gate.Lock()
	a.gateHeld = true
	return func() {
		a.gateHeld = false
		a.gate.Unlock()
	}
}

// driverChange runs one live command that makes the driver restart its
// BSSes or rebuild its channel list (dfs.go: the region, a channel move
// with its CSA and CAC) from Tick as from Apply (a.mu held): the gate's
// write side is held (taken here unless Apply or Rollback holds it), and
// the quiet time starts before the command, so no collector read starts
// while the driver works.
func (a *Applier) driverChange(ctx context.Context, quiet time.Duration, name string, args ...string) error {
	if !a.gateHeld {
		defer a.changingRadios()()
	}
	a.quietFor(quiet)
	return a.run(ctx, name, args...)
}

// restarted starts the settle time of a radio restart that just ended.
func (a *Applier) restarted() {
	a.quietFor(a.o.Settle) // a longer quiet time (a CAC: dfs.go) is kept
}
