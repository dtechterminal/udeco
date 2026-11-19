// SPDX-License-Identifier: GPL-2.0-or-later

package main

// WLAN broadcast schedules. translate.IntentFromCfg turns the controller's
// wireless.N.schedule_* into end-exclusive weekly windows ("mon 0800-1730",
// "2400" = midnight; nil = always on). The worker evaluates them every
// scheduleEvery in the unit's local time and switches SSIDs by applying the
// Desired with the SSIDs that are off disabled.

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

// bcmwifi deliberately has no per-SSID switch: a scheduled-off SSID must
// stay off through bcmwifi's Verify, Tick and Rollback, which only a Desired
// with that SSID disabled guarantees. The cost is one apply per window edge
// (hostapd restarts on the radios whose SSID set changed).

// scheduleOn reports whether now falls in one of the windows.
func scheduleOn(windows []string, now time.Time) bool {
	day := strings.ToLower(now.Weekday().String()[:3])
	m := now.Hour()*60 + now.Minute()
	for _, w := range windows {
		d, span, ok := strings.Cut(w, " ")
		if !ok || d != day {
			continue
		}
		a, b, ok := strings.Cut(span, "-")
		if !ok {
			continue
		}
		from, to := hhmm(a), hhmm(b)
		if from >= 0 && to >= 0 && from <= m && m < to {
			return true
		}
	}
	return false
}

// hhmm is "HHMM" in minutes (00:00-24:00); -1 when malformed.
func hhmm(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil || len(s) != 4 || v%100 >= 60 || v > 2400 {
		return -1
	}
	return v/100*60 + v%100
}

// scheduleOff lists the enabled WLANs (by id) whose schedule is off at now.
func scheduleOff(d bcmwifi.Desired, now time.Time) map[string]bool {
	off := map[string]bool{}
	for _, s := range d.SSIDs {
		if s.Enabled && s.Schedule != nil && !scheduleOn(s.Schedule, now) {
			off[s.ID] = true
		}
	}
	return off
}

// withSSIDsOff is d with the WLANs in off disabled (d is not changed).
func withSSIDsOff(d bcmwifi.Desired, off map[string]bool) bcmwifi.Desired {
	if len(off) == 0 {
		return d
	}
	d.SSIDs = append([]bcmwifi.SSID{}, d.SSIDs...)
	for i := range d.SSIDs {
		if off[d.SSIDs[i].ID] {
			d.SSIDs[i].Enabled = false
		}
	}
	return d
}

func sameSet(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func setKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// scheduleTick switches SSIDs whose schedule changed state (worker).
func (a *agent) scheduleTick(ctx context.Context) {
	w := &a.worker
	if w.full == nil || w.hold != "" {
		return
	}
	off := scheduleOff(*w.full, a.o.now())
	if sameSet(off, w.schedOff) {
		return
	}
	a.logf("wifi: schedule: WLANs off now: %v (were %v)", setKeys(off), setKeys(w.schedOff))
	d := withSSIDsOff(*w.full, off)
	p, err := a.wifi.Plan(ctx, d)
	if err != nil {
		a.logf("wifi: schedule: plan: %v (nothing changed)", err)
		return
	}
	if !p.Empty() {
		err = a.wifiChange(func() error { return a.wifi.Apply(ctx, p) })
		if errors.Is(err, bcmwifi.ErrDesiredFailed) {
			a.logf("wifi: schedule: this Wi-Fi failed to apply before: not retried (%v)", err)
			return
		}
		a.o.col.Invalidate()
		if err != nil {
			prev := w.applied
			a.wifiFailed(ctx, "schedule apply", err)
			if a.takeover.Load() && prev != nil {
				w.applied = prev
			}
			return
		}
	}
	w.schedOff = off
	a.markApplied(d)
}
