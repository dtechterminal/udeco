// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Ports the loop guard (topology.go, R9) took out of br-lan are put back
// whenever the agent stops changing the unit: dropToObserve's
// decosys.Restore does it from the run-dir record (decosys
// Options.LoopGuardFile), and an agent that starts in observe mode (forced
// by the marker, or configured) while an earlier takeover run's record is
// still on ramfs does it at start. A port left out of br-lan could later be
// the unit's only cable, and observe mode would never bring it back.

import (
	"context"
	"path/filepath"

	"github.com/dtechterminal/udeco/internal/decosys"
)

// loopGuardDevPath is the loop guard's record as a device path (decosys
// joins it onto its Root).
func (a *agent) loopGuardDevPath() string { return filepath.Join(a.o.runDir, loopFile) }

// observeLoopGuardRestore puts back the ports an earlier takeover run's loop
// guard took out (observe-mode start, before the loop runs). It builds a
// decosys handle for that alone and only when there is a record; nothing else
// on the unit changes.
func (a *agent) observeLoopGuardRestore(ctx context.Context) {
	if len(a.topo.removed) == 0 {
		return
	}
	sys := a.o.newSys(decosys.Options{Root: a.o.root, Run: a.o.run, Logf: a.logf, LoopGuardFile: a.loopGuardDevPath()})
	a.event("observe mode: putting the ports an earlier takeover run's loop guard took out back into br-lan")
	if err := sys.RestoreLoopGuard(ctx); err != nil {
		a.logf("loop guard: restore: %v (reboot the unit to rebuild br-lan)", err)
	}
	a.topo.removed = loadLoopGuard(a.loopFilePath())
}
