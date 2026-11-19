// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Controller actions (device.Outcome.Actions). In observe mode nothing on
// the unit changes: every action is logged only (a restart or upgrade is
// faked by the session, as for any emulated AP).

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
)

func (a *agent) action(ctx context.Context, act string) {
	verb, arg, _ := strings.Cut(act, ":")
	if !a.takeover.Load() {
		switch verb {
		case "unblock", "guest-auth", "guest-unauth":
		case "rate-update":
			a.logf("observe mode: per-client speed limit for %s kept, applied at takeover", arg)
		default:
			a.logf("observe mode: %s logged only, nothing on the unit changes", act)
		}
		return
	}
	switch verb {
	case "reboot":
		a.rebootReq = true // after this reply is handled and the state saved
	case "led":
		mode := bcmwifi.LEDOff
		if arg == "on" {
			mode = bcmwifi.LEDOn
		}
		a.submit("led "+mode, func(ctx context.Context) { a.led(ctx, mode) })
	case "locate":
		mode := bcmwifi.LEDLocateOff
		if arg == "on" {
			mode = bcmwifi.LEDLocate
		}
		a.submit("locate "+arg, func(ctx context.Context) { a.led(ctx, mode) })
	case "kick":
		mac := arg // strings.Cut keeps the rest, colons included
		a.submit("kick", func(ctx context.Context) {
			if err := a.wifi.Kick(ctx, mac); err != nil {
				a.logf("kick %s: %v", mac, err)
			}
		})
	case "block":
		list := append([]string{}, a.x.S.Blocked...)
		a.submit("blocked list", func(ctx context.Context) { a.setBlocked(ctx, list) })
	case "unblock":
		// the whole new list arrives with the "block" action
	case "scan":
		a.startScan(ctx, []string{"ng", "na"})
	case "spectrum-scan":
		a.spectrumScan(ctx)
	case "quick-scan":
		band, bws, _ := strings.Cut(arg, ":")
		if band == "6e" {
			// no rows and no change to any table (design §6.5)
			a.logf("[quick-scan] band 6e: the unit has no 6 GHz radio; nothing scanned")
			return
		}
		bw, _ := strconv.Atoi(bws) // 0 or junk: the runner makes it 20
		a.quickScan(ctx, band, bw)
	case "guest-auth", "guest-unauth":
		mac, on := arg, verb == "guest-auth"
		a.submit(verb+" "+mac, func(ctx context.Context) { a.guestAuth(ctx, mac, on) })
	case "rate-update":
		a.pushClientRates("rate-update " + arg)
	default:
		a.logf("action %q: ignored", act)
	}
}

// startScan runs the neighbour scan (`cmd scan`) off the inform loop and
// informs right after it.
func (a *agent) startScan(ctx context.Context, bands []string) {
	a.neighbourScan(ctx, neighbourJob{what: "scan", bands: bands})
}

// neighbourScan runs the collector's neighbour scan of j.bands off the
// inform loop, informs at its start (j.quick: quickscan_scanning) and right
// after it (`cmd scan`, or a spectrum command on a collector without a
// spectrum runner: sitesurvey.go).
func (a *agent) neighbourScan(ctx context.Context, j neighbourJob) {
	if a.shed.Load() {
		a.logf("%s: skipped, memory is low (R4)", j.label())
		return
	}
	if why := a.scanBlock(); why != "" {
		a.logf("%s: skipped, %s", j.label(), why)
		return
	}
	a.bg.Add(1)
	busy, started := a.scans.neighbourScan(ctx, a.o.col, j, a.t.scanTO, a.logf, a.scanBlock, func() {
		defer a.bg.Done()
		a.wakeLoop()
	})
	if !started {
		a.bg.Done()
		a.logf("%s: skipped: already in progress (%s)", j.label(), busy)
		return
	}
	a.wakeLoop()
}

// guestAuth lets an authorised guest past the guest chains, or takes it
// out again (worker). bcmwifi keeps the list for this boot, flushes the
// guest's flows and, on unauthorise, kicks it.
func (a *agent) guestAuth(ctx context.Context, mac string, on bool) {
	f, what := a.wifi.AuthorizeGuest, "authorise"
	if !on {
		f, what = a.wifi.UnauthorizeGuest, "unauthorise"
	}
	if err := f(ctx, mac); err != nil {
		a.logf("guest %s %s: %v", what, mac, err)
	}
}

// guestsDue returns the authorised guests (session state, persistent) whose
// authorisation has expired, and removes them from the session (loop
// goroutine). The controller sends no unauthorize-guest at expiry: a UAP
// expires them itself.
func (a *agent) guestsDue(now time.Time) []string {
	x := a.x
	x.GuestMu.Lock()
	defer x.GuestMu.Unlock()
	var due []string
	for mac, end := range x.S.Guests {
		if end <= now.Unix() {
			due = append(due, mac)
			delete(x.S.Guests, mac)
		}
	}
	sort.Strings(due)
	return due
}

// expireGuests unauthorises the guests whose time is up (loop goroutine).
func (a *agent) expireGuests(now time.Time) {
	due := a.guestsDue(now)
	if len(due) == 0 {
		return
	}
	if err := a.x.S.Save(a.statePath); err != nil {
		a.logf("saving state: %v", err)
	}
	for _, mac := range due {
		a.logf("guest %s: authorisation expired", mac)
		if a.takeover.Load() {
			a.submit("guest-unauth "+mac, func(ctx context.Context) { a.guestAuth(ctx, mac, false) })
		}
	}
}

// authorizedGuests is the session's unexpired guests, sorted (startup: the
// RunDir list bcmwifi keeps is gone after a reboot).
func (a *agent) authorizedGuests(now time.Time) []string {
	x := a.x
	x.GuestMu.Lock()
	defer x.GuestMu.Unlock()
	var out []string
	for mac, end := range x.S.Guests {
		if end > now.Unix() {
			out = append(out, mac)
		}
	}
	sort.Strings(out)
	return out
}
