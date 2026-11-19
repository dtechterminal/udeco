// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"sync"
	"testing"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
)

// gateWifi is a Wi-Fi backend with mtkwifi's restart gate.
type gateWifi struct{ *fakeWifi }

func (gateWifi) DriverRead() (func(), bool) { return func() {}, true }

// gateCol is a collector that follows the applier's restarts.
type gateCol struct {
	*fakeCol
	mu   sync.Mutex
	gate mtkwifi.RestartGate
}

func (c *gateCol) FollowRestarts(g mtkwifi.RestartGate) {
	c.mu.Lock()
	c.gate = g
	c.mu.Unlock()
}

func (c *gateCol) followed() mtkwifi.RestartGate {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gate
}

// TestCollectorFollowsRadioRestarts: in takeover mode the collector is
// handed the Wi-Fi applier's restart gate at setup, so the inform loop,
// the live view and the home listen keep off the driver while the agent
// restarts a radio (mtkwifi restartgate.go).
func TestCollectorFollowsRadioRestarts(t *testing.T) {
	var w gateWifi
	var col *gateCol
	h := newHarness(t, func(c *Config, o *options) {
		c.Takeover = true
		col = &gateCol{fakeCol: o.col.(*fakeCol)}
		o.col = col
		nw := o.newWifi
		o.newWifi = func(bo bcmwifi.Options) wifiApplier {
			w = gateWifi{nw(bo).(*fakeWifi)}
			return w
		}
	})
	h.start()
	eventually(t, "the collector follows the applier's restarts", func() bool { return col.followed() != nil })
	if g, ok := col.followed().(gateWifi); !ok || g.fakeWifi != w.fakeWifi {
		t.Fatalf("the collector follows %T, not the Wi-Fi applier", col.followed())
	}
}
