// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"fmt"
)

// TickReport is what one Tick found and did.
type TickReport struct {
	// Foreign lists state the agent did not set, found and (unless
	// NeedsApply) removed: TP-Link driver MAC filter entries, WDS peer ports
	// (audit D8), vifs dropped from their bridge (D14), an unused vif up, a
	// client vif with dwds on, missing guest chains or jumps.
	Foreign []string
	// Steps is the number of repair steps run.
	Steps int
	// NeedsApply means the drift can only be fixed by a full Plan+Apply
	// (TP-Link's hostapd back, our hostapd gone, the PHY or a conf changed).
	// Tick changed nothing in that case.
	NeedsApply bool
	// RateLimitChanges is the number of stations whose tc limit was added,
	// changed or removed.
	RateLimitChanges int
	// Radar lists the radar moves found since the last Tick (dfs.go):
	// each is reported once.
	Radar []RadarEvent
	// NeighborChanges is the number of 802.11k neighbor list entries added
	// or removed (neighbors.go).
	NeighborChanges int
	// Problems lists repairs that failed.
	Problems []string
}

// current is the Desired the agent owns Wi-Fi with: the one applied in this
// process, else the saved last-good while the agent's hostapd serves BSSes.
// nil when the agent does not own Wi-Fi.
func (a *Applier) current() *Desired {
	if a.applied != nil {
		d := a.applied.clone()
		return &d
	}
	if len(a.ourVifs()) > 0 {
		if lg, err := a.loadLastGood(); err == nil && lg != nil {
			return lg
		}
	}
	return nil
}

// Tick re-checks the live state against the applied Desired and repairs, in
// place, what can be repaired without restarting hostapd: driver MAC
// filters (compared with the live driver; foreign entries removed and
// reported), WDS peers bridged by TP-Link's hotplug (audit D8, R10d), a
// client vif's dwds, vifs netifd dropped from their bridges (D14, R10c), the
// placeholder wlN1 or another unused vif that came up, the guest ebtables chains, and the
// per-client rate limits for the stations associated now. Each datapath
// repair is followed by a flow-cache flush (R21). The agent calls it every
// tick (60 s) while it owns Wi-Fi; it does nothing when the agent does not
// own Wi-Fi, and with DryRun it only logs. Each radio's TWT state is logged
// when it changes; one that differs from the config is set only inside a
// radio down/up Tick makes anyway (a client vif's dwds), never by a restart
// of its own (twt.go).
func (a *Applier) Tick(ctx context.Context) (TickReport, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var r TickReport
	d := a.current()
	if d == nil {
		return r, nil
	}
	p, err := a.plan(ctx, *d)
	if err != nil {
		return r, err
	}
	r.Foreign = p.Foreign
	r.Radar = a.takeRadar()
	if len(p.cac) > 0 {
		// A radio in its channel availability check does not beacon for
		// about a minute: no repair (a radio down/up would start it over)
		// and no full apply until it ends.
		a.o.Logf("bcmwifi: tick: %v in a DFS channel availability check: no repair until it ends", p.cac)
		return r, nil
	}
	if p.disruptive {
		r.NeedsApply = true
		r.Problems = append(r.Problems, "live Wi-Fi state differs in a way only a full apply fixes")
		return r, nil
	}
	for _, f := range p.Foreign {
		a.o.Logf("bcmwifi: tick: foreign state: %s", f)
	}
	a.logTWT(p)
	if a.o.DryRun {
		a.logPlan("dry-run tick", p)
		return r, nil
	}
	a.backfillBaseline(ctx) // parity.go: before the first change of this process
	if len(p.Steps) > 0 {
		r.Steps = len(p.Steps)
		if err := a.executeAll(ctx, p.Steps); err != nil {
			r.Problems = append(r.Problems, fmt.Sprintf("repair: %v", err))
		}
	}
	n, err := a.syncShaping(ctx, a.layout(*d))
	r.RateLimitChanges = n
	if err != nil {
		r.Problems = append(r.Problems, err.Error())
	}
	nc, probs := a.syncNeighbors(ctx, a.layout(*d), a.now())
	r.NeighborChanges = nc
	r.Problems = append(r.Problems, probs...)
	return r, nil
}
