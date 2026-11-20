// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// TestKickedLeaveStatus: a station the minimum RSSI kick disconnected
// leaves with assoc_status 16 (as the U6's stamgr reports it); a later
// leave of the same station is a plain one again.
func TestKickedLeaveStatus(t *testing.T) {
	var e staEvents
	e.observe(staReading(100, map[string][][2]any{"ra0": {{"aa:bb:cc:dd:ee:01", -88}}}), nil)
	e.kicked([]string{"aa:bb:cc:dd:ee:01"})
	e.observe(staReading(110, map[string][][2]any{"ra0": {}}), nil)
	if len(e.queue) != 1 || e.queue[0]["event_type"] != staEvLeave || e.queue[0]["assoc_status"] != kickStatus {
		t.Fatalf("queue %v", e.queue)
	}
	e.queue = nil
	e.observe(staReading(120, map[string][][2]any{"ra0": {{"aa:bb:cc:dd:ee:01", -60}}}), nil)
	e.observe(staReading(130, map[string][][2]any{"ra0": {}}), nil)
	if len(e.queue) != 2 || e.queue[1]["event_type"] != staEvLeave {
		t.Fatalf("queue %v", e.queue)
	}
	if _, ok := e.queue[1]["assoc_status"]; ok {
		t.Errorf("a plain leave carries %v", e.queue[1]["assoc_status"])
	}
}

type kickWifi struct {
	wifiApplier
	snaps int
	kick  []string
}

func (k *kickWifi) KickWeak(_ context.Context, s *apstate.Snapshot) []string {
	k.snaps++
	return k.kick
}

// TestGarageReadingKicks: on platform jio-mtk in takeover, each fresh
// reading goes to the applier's minimum RSSI kick, and what it kicked is
// marked for the leave events.
func TestGarageReadingKicks(t *testing.T) {
	a := &agent{cfg: &Config{Platform: PlatformJio, Takeover: true}}
	a.takeover.Store(true)
	w := &kickWifi{kick: []string{"aa:bb:cc:dd:ee:01"}}
	a.wifi = w
	a.garageReading(context.Background(), &apstate.Snapshot{})
	if w.snaps != 1 || len(a.sta.kicks) != 1 {
		t.Errorf("snaps %d kicks %v", w.snaps, a.sta.kicks)
	}
	a.cfg.Platform = ""
	a.garageReading(context.Background(), &apstate.Snapshot{})
	if w.snaps != 1 {
		t.Error("the Deco ran the Garage's kick")
	}
}
