// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// While the uplink-loss hold stands, a reading with only one other port
// up (a wired client on eth0) and no gateway evidence must not re-elect
// that port as the uplink and lift the hold: the network is still gone.
// A real cable move (the gateway's MAC learned on eth0) still does.
func TestUplinkHoldNotLiftedByOtherPort(t *testing.T) {
	u := newUpUnit(t, nil)
	carr := map[string]bool{"eth0": true, "eth1": true}
	u.h.a.o.carrier = func(dev string) (bool, bool) { v, ok := carr[dev]; return v, ok }
	u.h.a.o.now = func() time.Time { return u.now }
	u.h.a.topo.uplink = "eth1"
	wantCalls(t, "steady", u.step(30*time.Second, true))
	carr["eth1"] = false
	wantCalls(t, "lost", u.step(5*time.Second, false), "ssids-down")
	// eth1 down flushed the gateway's FDB entry; only eth0 has carrier
	u.h.a.observeReading(&apstate.Snapshot{Gateway: "192.168.0.1", Ports: []apstate.Port{
		{Name: "eth0", Up: true, BridgePort: 1}, {Name: "eth1", Up: false, BridgePort: 2}}}, map[string]any{})
	wantCalls(t, "other port with carrier", u.step(30*time.Second, false))
	if up, _ := u.h.a.topo.uplinkName.Load().(string); up != "eth1" {
		t.Errorf("uplink moved to %q during the hold without gateway evidence", up)
	}
	// the cable moved: the gateway answers on eth0
	u.h.a.observeReading(fdbReading(true, 1), map[string]any{})
	wantCalls(t, "cable moved", u.step(11*time.Second, false), "ssids-up")
}

// A hold change whose job the full worker queue dropped is a failed
// change: it is tried again, not taken as done.
func TestUplinkDroppedJobRetried(t *testing.T) {
	u := newUpUnit(t, nil)
	wantCalls(t, "steady", u.step(30*time.Second, true))
	wantCalls(t, "4 s lost", u.step(4*time.Second, false))
	for len(u.h.a.jobs) < cap(u.h.a.jobs) {
		u.h.a.jobs <- job{"filler", func(context.Context) {}}
	}
	u.now = u.now.Add(time.Second)
	u.h.a.uplinkPass(u.now) // the down job is dropped
	for len(u.h.a.jobs) > 0 {
		(<-u.h.a.jobs).fn(context.Background())
	}
	wantCalls(t, "retried", u.step(15*time.Second, false), "ssids-down")
}
