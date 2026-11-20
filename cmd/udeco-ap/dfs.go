// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"errors"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// DFS (docs/deco/features/dfs.md). bcmwifi follows a radar move and
// reports it once from Tick (worker goroutine); the agent sends it as a
// U6 Pro does, an EVT_AP_RadarDetected notification ("radar found on
// channel %u (%u MHz)", ubntbox) with the quick-scan event's keys, through
// the station-event queue (one notification inform each). The
// controller's nightly cron job `syswrapper.sh dfs-reset` (translate
// cron.go) calls bcmwifi's DFSReset and, when a radio goes back, applies.

// radarIn queues radar moves for the controller (worker goroutine).
func (a *agent) radarIn(evs []bcmwifi.RadarEvent) {
	if len(evs) == 0 {
		return
	}
	a.radarMu.Lock()
	defer a.radarMu.Unlock()
	for _, ev := range evs {
		a.logf("wifi: radar on %s channel %d (%d MHz): the driver moved %s to %s", ev.Radio, ev.Channel, ev.FreqMHz, ev.From, ev.To)
		a.radarQ = append(a.radarQ, ev)
	}
}

// radarOut takes the queued radar moves (loop goroutine).
func (a *agent) radarOut() []bcmwifi.RadarEvent {
	a.radarMu.Lock()
	defer a.radarMu.Unlock()
	q := a.radarQ
	a.radarQ = nil
	return q
}

// radarPayload is the EVT_AP_RadarDetected notification payload.
func radarPayload(ev bcmwifi.RadarEvent, radioName string) map[string]any {
	return map[string]any{"event_string": "EVT_AP_RadarDetected", "radio": ev.Band, "radio_name": radioName,
		"channel": ev.Channel, "freq": ev.FreqMHz}
}

// radarEvents puts the queued radar moves on the station-event queue
// (loop goroutine).
func (a *agent) radarEvents() {
	for _, ev := range a.radarOut() {
		name := ""
		for _, r := range a.x.Dev.Radios {
			if r.Radio == ev.Band {
				name = r.Name
			}
		}
		a.sta.push(radarPayload(ev, name))
	}
}

// dfsResetDue: a dfs-reset time has passed since last (a check, or the
// agent's start: a zero last is never due). A reset missed while the agent
// was down runs at the next check.
func dfsResetDue(now time.Time, at translate.DailyTime, last time.Time) bool {
	if last.IsZero() {
		return false
	}
	due := time.Date(now.Year(), now.Month(), now.Day(), at.Hour, at.Minute, 0, 0, now.Location())
	if now.Before(due) {
		due = due.AddDate(0, 0, -1)
	}
	return last.Before(due)
}

// dfsResetter is a Wi-Fi backend with the controller's dfs-reset.
type dfsResetter interface {
	DFSReset(ctx context.Context) bool
}

// dfsResetTick runs the controller's dfs-reset when due (worker).
func (a *agent) dfsResetTick(ctx context.Context) {
	w := &a.worker
	r, ok := a.wifi.(dfsResetter)
	if !ok || w.dfsReset == nil || w.applied == nil || w.hold != "" {
		return
	}
	now := a.o.now()
	if w.dfsResetAt.IsZero() {
		w.dfsResetAt = now // the clock starts here
		return
	}
	if !dfsResetDue(now, *w.dfsReset, w.dfsResetAt) {
		return
	}
	w.dfsResetAt = now
	if !r.DFSReset(ctx) {
		return
	}
	d := *w.applied
	p, err := a.wifi.Plan(ctx, d)
	if err != nil || p.Empty() {
		return
	}
	a.logf("wifi: dfs-reset: back to the controller's DFS channel (%d step(s))", len(p.Steps))
	err = a.wifiChange(func() error { return a.wifi.Apply(ctx, p) })
	a.o.col.Invalidate()
	if err != nil && !errors.Is(err, bcmwifi.ErrDesiredFailed) {
		prev := w.applied
		a.wifiFailed(ctx, "dfs-reset apply", err)
		if a.takeover.Load() && prev != nil {
			w.applied = prev
		}
	}
}
