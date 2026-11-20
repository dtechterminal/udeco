// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Uplink loss (docs/deco/features/uplink-loss.md). A U6 whose wired uplink
// goes away takes its user and guest SSIDs down, so clients roam to an AP
// that still reaches the network instead of staying on one that does not;
// it brings them back when the uplink returns. Here:
//
//   - the tracked uplink port (topology.go) is read every uplinkPoll
//     (/sys/class/net/<port>/carrier); without carrier for uplinkLostAfter
//     the SSIDs go down (bcmwifi.SSIDsDown: `wl bss down` on every BSS the
//     agent serves; no radio restart, hostapd keeps running, and Plan,
//     Tick, every apply and Verify keep them down while the hold lasts);
//   - with carrier again for uplinkBackAfter they come back up;
//   - with uplink_gateway_down (default off) a gateway that answers no
//     ICMP echo for gwDownAfter does the same with the carrier up (the
//     agent's own probe every gwProbeEvery; pathmon is the controller's
//     and may be off); an answer brings them back;
//   - never during a Wi-Fi apply or rollback (wifiBusy) or while a takeover
//     hold stands (a TP-Link rebuild or upgrade, scanHold): the change
//     waits for its end;
//   - each change is logged and kept as an event; a failed change is
//     retried after uplinkRetry;
//   - takeover with the Wi-Fi live only; a drop to observe mode forgets
//     the hold (the hand-back restored TP-Link's BSSes);
//   - the LED shows the hold as TP-Link's conn "ap-lost" red blink (set by
//     bcmwifi with the SSIDs); the agent's stop puts conn "online" back
//     (releaseLED).
//
// uplink_ssid_down false turns it off: it is the one behaviour here that
// takes the unit's own Wi-Fi away, so it has a key. Deco only (the
// Garage's Wi-Fi backend has no hold).

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/pathmon"
)

const (
	uplinkLostAfter = 5 * time.Second  // no carrier this long: SSIDs down
	uplinkBackAfter = 10 * time.Second // carrier this long: SSIDs up
	uplinkRetry     = 10 * time.Second // a failed change is tried again after this
	gwDownAfter     = 60 * time.Second // gateway unanswered this long (uplink_gateway_down)
	gwProbeEvery    = 5 * time.Second
	gwProbeTimeout  = time.Second
)

// ssidHolder is bcmwifi's uplink-loss hold.
type ssidHolder interface {
	SSIDsDown(ctx context.Context, down bool) error
}

var _ ssidHolder = (*bcmwifi.Applier)(nil)

// ledReleaser is bcmwifi's way back from the uplink-loss LED blink (conn
// "ap-lost" while the hold stands; bcmwifi uplinkled.go).
type ledReleaser interface {
	ReleaseLED(ctx context.Context)
}

var _ ledReleaser = (*bcmwifi.Applier)(nil)

// releaseLED leaves no uplink-loss blink behind when the agent stops (the
// SSIDs stay as they are, as for every stop): nothing would clear it. The
// worker has ended; SIGTERM cancelled ctx, so the call gets its own bound.
func (a *agent) releaseLED() {
	r, ok := a.wifi.(ledReleaser)
	if !ok {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r.ReleaseLED(ctx)
}

// uplinkGuard is the watcher's state (its goroutine), but for the atomics.
type uplinkGuard struct {
	down       bool      // the SSIDs are held down by the agent
	lostAt     time.Time // start of the current run without carrier (zero: carrier)
	backAt     time.Time // start of the current run with carrier (zero: none)
	last       time.Time // the last pass that read the carrier
	retryAt    time.Time // a failed change is not tried before this
	waitLogged string    // why a change waits, logged once
	noHold     bool      // "no hold on this backend" logged

	failed atomic.Bool // worker -> watcher: the last change failed
	// held: the SSIDs are held down (watcher -> topology): while it
	// stands, a reading without gateway evidence does not move the uplink
	// to another port with carrier (a wired client), which would lift the
	// hold on an AP that still has no path to the network.
	held   atomic.Bool
	gwFail atomic.Int64 // unix ns of the first unanswered gateway probe of the run (0: answered, or no gateway)
}

// uplinkSSIDDown: on unless uplink_ssid_down is false.
func (c *Config) uplinkSSIDDown() bool { return c.UplinkSSIDDown == nil || *c.UplinkSSIDDown }

// startUplinkWatch starts the watcher (takeover, Deco, uplink_ssid_down).
func (a *agent) startUplinkWatch(ctx context.Context) {
	if a.cfg.jio() || !a.cfg.uplinkSSIDDown() {
		return
	}
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		t := time.NewTicker(a.t.uplinkPoll)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			a.uplinkPass(a.o.now())
		}
	}()
	if !a.cfg.UplinkGatewayDown {
		return
	}
	p := a.o.pmProber
	if p == nil {
		p = &pathmon.ICMP{}
	}
	a.bg.Add(1)
	go func() {
		defer a.bg.Done()
		t := time.NewTicker(a.t.gwProbe)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			a.gwProbe(ctx, p, a.o.now())
		}
	}()
}

// readCarrier reads a port's carrier from sysfs (ok false: unreadable).
func (a *agent) readCarrier(dev string) (up, ok bool) {
	b, err := os.ReadFile(filepath.Join(a.o.root, "sys/class/net", dev, "carrier"))
	if err != nil {
		return false, false
	}
	return strings.TrimSpace(string(b)) == "1", true
}

// gwProbe sends one echo to the gateway and keeps the run of failures.
func (a *agent) gwProbe(ctx context.Context, p pathmon.Prober, now time.Time) {
	gw, _ := a.topo.gwIP.Load().(string)
	ip := net.ParseIP(gw)
	if ip == nil || ip.To4() == nil {
		a.upl.gwFail.Store(0)
		return
	}
	if _, err := p.Probe(ctx, ip, 56, gwProbeTimeout); err == nil {
		a.upl.gwFail.Store(0)
		return
	}
	a.upl.gwFail.CompareAndSwap(0, now.UnixNano())
}

// uplinkPass is one look at the uplink (watcher goroutine).
func (a *agent) uplinkPass(now time.Time) {
	g := &a.upl
	if g.failed.Swap(false) {
		g.down = !g.down // not done: the change is due again
		g.held.Store(g.down)
		g.retryAt = now.Add(uplinkRetry)
	}
	if !a.takeover.Load() || a.policy.Load() == nil {
		g.down, g.lostAt, g.backAt, g.last = false, time.Time{}, time.Time{}, time.Time{}
		g.held.Store(false)
		return
	}
	dev, _ := a.topo.uplinkName.Load().(string)
	carrier, ok := false, false
	if dev != "" {
		carrier, ok = a.o.carrier(dev)
	}
	if !ok {
		g.lostAt, g.backAt, g.last = time.Time{}, time.Time{}, time.Time{}
		return
	}
	// a run starts at the last pass that read the other state
	since := g.last
	if since.IsZero() {
		since = now
	}
	g.last = now
	if carrier {
		g.lostAt = time.Time{}
		if g.backAt.IsZero() {
			g.backAt = since
		}
	} else {
		g.backAt = time.Time{}
		if g.lostAt.IsZero() {
			g.lostAt = since
		}
	}
	gwSince := int64(0)
	if a.cfg.UplinkGatewayDown {
		gwSince = g.gwFail.Load()
	}
	gwDown := gwSince != 0 && now.Sub(time.Unix(0, gwSince)) >= gwDownAfter
	var why string
	want := g.down
	switch {
	case !g.down && !carrier && now.Sub(g.lostAt) >= uplinkLostAfter:
		want, why = true, fmt.Sprintf("uplink %s lost (no carrier for %s): SSIDs down", dev, now.Sub(g.lostAt).Round(time.Second))
	case !g.down && gwDown:
		want, why = true, fmt.Sprintf("uplink %s lost (gateway unanswered for %s): SSIDs down", dev, now.Sub(time.Unix(0, gwSince)).Round(time.Second))
	case g.down && carrier && now.Sub(g.backAt) >= uplinkBackAfter && gwSince == 0:
		want, why = false, fmt.Sprintf("uplink %s back (carrier for %s): SSIDs up", dev, now.Sub(g.backAt).Round(time.Second))
	}
	if want == g.down || now.Before(g.retryAt) {
		return
	}
	hold, _ := a.scanHold.Load().(string)
	wait := ""
	switch {
	case a.wifiBusy.Load():
		wait = "a Wi-Fi apply runs"
	case hold != "":
		wait = hold
	}
	if wait != "" {
		if wait != g.waitLogged {
			g.waitLogged = wait
			a.logf("uplink %s: SSIDs down=%t waits: %s", dev, want, wait)
		}
		return
	}
	g.waitLogged = ""
	h, ok := a.wifi.(ssidHolder)
	if !ok {
		if !g.noHold {
			g.noHold = true
			a.logf("uplink %s: the Wi-Fi backend cannot take the SSIDs down", dev)
		}
		return
	}
	if !a.submit("uplink ssids", func(ctx context.Context) {
		if err := h.SSIDsDown(ctx, want); err != nil {
			a.logf("uplink: SSIDs down=%t: %v", want, err)
			g.failed.Store(true)
		}
	}) {
		g.retryAt = now.Add(uplinkRetry) // dropped: not done, due again
		return
	}
	g.down = want
	g.held.Store(want)
	a.event(why)
}
