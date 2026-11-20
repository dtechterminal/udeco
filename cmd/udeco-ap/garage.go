// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// The Garage's (platform jio-mtk) per-reading Wi-Fi jobs: what a U6's
// stamgr and wevent do with each look at the clients
// (docs/deco/features/garage-parity.md).

// weakKicker is the applier's minimum RSSI kick (mtkwifi minrssi.go).
type weakKicker interface {
	KickWeak(context.Context, *apstate.Snapshot) []string
}

// garageReading runs after a fresh reading's station events were taken
// (loop goroutine). The kicked stations' leaves carry assoc_status 16.
func (a *agent) garageReading(ctx context.Context, s *apstate.Snapshot) {
	if !a.cfg.jio() || !a.takeover.Load() {
		return
	}
	if k, ok := a.wifi.(weakKicker); ok {
		a.sta.kicked(k.KickWeak(ctx, s))
	}
}
