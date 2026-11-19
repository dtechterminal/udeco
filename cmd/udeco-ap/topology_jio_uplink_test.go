// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"testing"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// On the JCOW414 the uplink is the WAN socket (eth0.4.1) by wiring. On
// 2026-11-19 the gateway's MAC was learned for 25 s on LAN port 1 (the
// tenant's router), and the tracker moved the uplink to eth0.1.1 and back.
// The gateway's MAC on a LAN port must not move it.
func TestJioUplinkPinned(t *testing.T) {
	a, events := topoAgent(t, true)
	a.cfg = &Config{Platform: PlatformJio, Model: "UHDIW"}
	a.topo.uplink, a.uplink = "eth0.4.1", "eth0.4.1"
	now := time.Date(2026, 11, 19, 18, 26, 14, 0, time.UTC)
	a.o.now = func() time.Time { return now }
	const gw = "1c:6a:1b:c5:04:c1"
	reading := func(gwPort int) *apstate.Snapshot {
		return &apstate.Snapshot{
			Gateway: "192.168.0.1",
			ARP:     map[string]string{gw: "192.168.0.1"},
			FDB:     []apstate.FDBEntry{{MAC: gw, Port: gwPort}},
			Ports: []apstate.Port{
				{Name: "eth0.1.1", Up: true, BridgePort: 1},
				{Name: "eth0.4.1", Up: true, BridgePort: 4},
			},
		}
	}
	for i, p := range []int{1, 1, 4, 1} {
		now = now.Add(5 * time.Second)
		a.observeReading(reading(p), map[string]any{})
		if a.topo.uplink != "eth0.4.1" || a.uplink != "eth0.4.1" {
			t.Fatalf("reading %d (gateway MAC on bridge port %d): uplink %q / %q, want eth0.4.1", i, p, a.topo.uplink, a.uplink)
		}
	}
	if u, _ := a.topo.uplinkName.Load().(string); u != "" && u != "eth0.4.1" {
		t.Errorf("uplinkName %q", u)
	}
	if n := countEvents(*events, "uplink moved"); n != 0 {
		t.Errorf("uplink moved %d times: %q", n, *events)
	}
	for len(a.jobs) > 0 {
		j := <-a.jobs
		if len(j.what) >= 6 && j.what[:6] == "uplink" {
			t.Errorf("queued %q", j.what)
		}
	}
}
