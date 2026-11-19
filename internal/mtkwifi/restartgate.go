// SPDX-License-Identifier: GPL-2.0-or-later

package mtkwifi

import (
	"time"
)

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
//     Settle (20 s) from its end.
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

func (a *Applier) settling() bool { return a.o.now().UnixNano() < a.quietUntil.Load() }

// changingRadios closes the gate for an Apply or Rollback (a.mu held):
// driver reads under way finish first, new ones are skipped until the
// returned func runs.
func (a *Applier) changingRadios() func() {
	a.gate.Lock()
	return a.gate.Unlock
}

// restarted starts the settle time of a radio restart that just ended.
func (a *Applier) restarted() {
	a.quietUntil.Store(a.o.now().Add(a.o.Settle).UnixNano())
}
