// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/hapdmon"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
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

// leaveSource is the Garage's driver leave monitor (mtkwifi.Events).
type leaveSource interface {
	Take() ([]hapdmon.Event, int)
}

// leaveWakeGap: a released leave wakes the loop at most this often.
const leaveWakeGap = 2 * time.Second

var lastLeaveWake atomic.Int64

// startDriverEvents follows the MediaTek drivers' station events
// (rtnetlink, ECNT, the MT7603's Del Sta lines): a leave reaches the
// controller with the next inform, which it brings forward
// (mtkwifi/drvevents.go). Takeover only; passive listeners.
func (a *agent) startDriverEvents(ctx context.Context) {
	if a.o.drvEv != nil {
		a.drv = a.o.drvEv
		return
	}
	m := mtkwifi.NewEvents(mtkwifi.EventsOptions{Logf: a.logf, Busy: a.radiosBusy, NG2: true,
		Notify: func() {
			now := time.Now().UnixNano()
			if last := lastLeaveWake.Load(); now-last >= int64(leaveWakeGap) && lastLeaveWake.CompareAndSwap(last, now) {
				a.wakeLoop()
			}
		}})
	a.drv = m
	a.bg.Add(1)
	go func() { defer a.bg.Done(); m.Run(ctx) }()
}

// radiosBusy: the Wi-Fi applier is changing the radios or a restart
// settles (its RestartGate refuses a driver read): driver events of that
// time are the restart's own.
func (a *agent) radiosBusy() bool {
	if a.wifiBusy.Load() {
		return true
	}
	g, ok := a.wifi.(mtkwifi.RestartGate)
	if !ok {
		return false
	}
	done, ok := g.DriverRead()
	if ok {
		done()
	}
	return !ok
}

// uplinkIsolator is the applier's uplink-loss isolation (mtkwifi
// uplinkloss.go).
type uplinkIsolator interface {
	SetUplinkDown(context.Context, bool) error
}

// uplinkState is the uplink-loss loop's state.
type uplinkState struct {
	w        mtkwifi.UplinkWatch
	isolated bool
}

// uplinkPoll: how often the uplink port's carrier is read.
const uplinkPoll = time.Second

// startUplinkLoss follows the uplink port's carrier (uplink_loss, on by
// default on the Garage; takeover with apply).
func (a *agent) startUplinkLoss(ctx context.Context) {
	if !a.cfg.uplinkLoss() || !a.cfg.Apply {
		return
	}
	if _, ok := a.wifi.(uplinkIsolator); !ok {
		return
	}
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		var st uplinkState
		t := time.NewTicker(uplinkPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-t.C:
				a.uplinkStep(ctx, &st, now)
			}
		}
	}()
}

// uplinkStep reads the uplink port's carrier once and isolates or
// restores the SSIDs when UplinkWatch says so. No switch reading (the
// port missing) is no decision.
func (a *agent) uplinkStep(ctx context.Context, st *uplinkState, now time.Time) {
	l, ok := jioports.ReadLinks(a.o.root)[jioports.UplinkPhys]
	if !ok {
		return
	}
	iso := st.w.Observe(l.Up, now)
	if iso == st.isolated {
		return
	}
	st.isolated = iso
	u, ok := a.wifi.(uplinkIsolator)
	if !ok {
		return
	}
	if iso {
		a.event("UPLINK LOST: no carrier on the uplink port for 15 s: user and guest SSIDs go down, the management SSID stays up")
	} else {
		a.event("UPLINK BACK: carrier on the uplink port for 30 s: every SSID comes back")
	}
	if err := u.SetUplinkDown(ctx, iso); err != nil {
		a.logf("wifi: %v", err)
	}
}
