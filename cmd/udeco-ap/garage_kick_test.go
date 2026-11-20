// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
)

// TestKickedLeaveStatus: a station the minimum RSSI kick disconnected
// leaves with assoc_status 16 (as the U6's stamgr reports it); a later
// leave of the same station is a plain one again (assoc_status 0).
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
	// every sta_leave carries assoc_status (the Deco's leave hints,
	// staevents.go): a plain one says 0
	if st, ok := e.queue[1]["assoc_status"]; !ok || st != 0 {
		t.Errorf("a plain leave carries assoc_status %v (present %v), want 0", st, ok)
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

// TestDriverLeaves: on the Garage, a driver Delete released before the
// reading started is the station's sta_leave in that reading (its own
// time as last_seen), never a second time from the diff; a station back
// in the reading is a new association; a Delete of a station the
// controller was never told about (authenticated only, a wrong
// passphrase) is no event; a kernel log Del Sta (any 2.4 GHz BSS) matches
// the station's 2.4 GHz BSS only.
func TestDriverLeaves(t *testing.T) {
	var e staEvents
	vifs := map[string]string{"ra0": "wifi0ap0", "ra1": "wifi0ap1", "rai1": "wifi1ap1"}
	t0 := time.Unix(1_800_000_000, 0)
	a, b, c := "aa:bb:cc:dd:ee:01", "aa:bb:cc:dd:ee:02", "aa:bb:cc:dd:ee:03"
	e.observe(staReading(100, map[string][][2]any{"wifi0ap0": {{a, -60}}, "wifi1ap1": {{b, -50}}, "wifi0ap1": {}}),
		&staFeed{read: t0, now: t0, vifs: vifs, leaves: true})
	evs := []hapdmon.Event{
		{Vif: "ra0", MAC: a, Kind: hapdmon.Disconnected, At: t0.Add(4 * time.Second)},
		{Vif: "rai1", MAC: c, Kind: hapdmon.Disconnected, At: t0.Add(5 * time.Second)},        // never associated
		{Vif: mtkwifi.AnyNG, MAC: b, Kind: hapdmon.Disconnected, At: t0.Add(5 * time.Second)}, // b is on 5 GHz
	}
	// the reading of t0+10 s still shows nothing of a (gone at t0+4 s)
	e.observe(staReading(110, map[string][][2]any{"wifi0ap0": {}, "wifi1ap1": {{b, -50}}, "wifi0ap1": {}}),
		&staFeed{read: t0.Add(10 * time.Second), now: t0.Add(10 * time.Second), vifs: vifs, evs: evs, leaves: true})
	if len(e.queue) != 1 || e.queue[0]["event_type"] != staEvLeave || e.queue[0]["mac"] != a || e.queue[0]["last_seen"] != int64(104) {
		t.Fatalf("queue %v", e.queue)
	}
	e.queue = nil
	// a reconnects within the same reading interval as its leave
	e.observe(staReading(120, map[string][][2]any{"wifi0ap0": {}, "wifi1ap1": {{b, -50}}, "wifi0ap1": {}}),
		&staFeed{read: t0.Add(20 * time.Second), now: t0.Add(20 * time.Second), vifs: vifs, leaves: true})
	if len(e.queue) != 0 {
		t.Fatalf("second leave: %v", e.queue)
	}
	e.observe(staReading(130, map[string][][2]any{"wifi0ap0": {{a, -61}}, "wifi1ap1": {{b, -50}}, "wifi0ap1": {}}),
		&staFeed{read: t0.Add(30 * time.Second), now: t0.Add(30 * time.Second), vifs: vifs, leaves: true})
	if len(e.queue) != 1 || e.queue[0]["event_type"] != staEvAssoc {
		t.Fatalf("queue %v", e.queue)
	}
	e.queue = nil
	// Del Sta from the kernel log for a: its 2.4 GHz BSS
	e.observe(staReading(140, map[string][][2]any{"wifi0ap0": {{a, -61}}, "wifi1ap1": {{b, -50}}, "wifi0ap1": {}}),
		&staFeed{read: t0.Add(40 * time.Second), now: t0.Add(40 * time.Second), vifs: vifs, leaves: true,
			evs: []hapdmon.Event{{Vif: mtkwifi.AnyNG, MAC: a, Kind: hapdmon.Disconnected, At: t0.Add(35 * time.Second)}}})
	// the reading (taken after the leave) shows a again: it came back
	if len(e.queue) != 2 || e.queue[0]["event_type"] != staEvLeave || e.queue[1]["event_type"] != staEvAssoc {
		t.Fatalf("queue %v", e.queue)
	}
}

type fakeLeaves struct{ evs []hapdmon.Event }

func (f *fakeLeaves) Take() ([]hapdmon.Event, int) { e := f.evs; f.evs = nil; return e, 0 }

// TestGarageFeed: on the Garage the reading's feed carries the driver
// leaves, marked as such, and no socket coverage.
func TestGarageFeed(t *testing.T) {
	a := &agent{cfg: &Config{Platform: PlatformJio, Takeover: true}}
	a.o.drvEv = &fakeLeaves{evs: []hapdmon.Event{{Vif: "ra0", MAC: "aa:bb:cc:dd:ee:01", Kind: hapdmon.Disconnected}}}
	a.startStaMonitor(context.Background())
	feed := a.staFeed(&apstate.Snapshot{}, map[string]any{})
	if feed == nil || !feed.leaves || len(feed.evs) != 1 || feed.since != nil {
		t.Fatalf("feed %+v", feed)
	}
	if a.hapd != nil {
		t.Error("hostapd monitor started on the Garage")
	}
}
