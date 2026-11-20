// SPDX-License-Identifier: GPL-2.0-or-later

package main

// The Wi-Fi worker: the only goroutine that changes the unit (decosys and
// bcmwifi). The inform loop submits jobs; the worker also runs the takeover
// tick every enforceEvery (every fastEnforce right after the boot gate):
// inbound fence, decosys.Enforce, egress, site users, then Wi-Fi (a pending
// provision, else bcmwifi.Tick and the health check), and every selfCheck
// the R10 summary.
//
// Ordering rules (agent-design.md §3.5, §3.7):
//   - the inbound fence (decosys.Ingress) is re-asserted before every
//     Enforce; it went in first in R1 phase 1;
//   - decosys.Enforce (awnd stopped, acsd2 killed) must have succeeded once
//     before bcmwifi pins any chanspec: a provision that arrives earlier
//     waits for it; so does one that meets a TP-Link Wi-Fi rebuild or a
//     firmware upgrade in flight (decosys Report.Guard, R17), and no health
//     rollback and no bcmwifi.Tick run during one;
//   - decosys.Egress(true) on every Enforce tick when egress is on;
//   - after every bcmwifi Apply or Rollback the collector's cached VAP
//     identities and caps are dropped (Collector.Invalidate);
//   - an Apply error or a Rollback that leaves Wi-Fi with TP-Link (or
//     bcmwifi.ErrNoBaseline) restores TP-Link's services (decosys.Restore)
//     and drops the agent to observe mode until reboot;
//   - the controller's blocked list goes to bcmwifi.SetBlocked before and
//     after every provision;
//   - a Desired that failed to apply is not retried: bcmwifi refuses it
//     with ErrDesiredFailed (changing nothing) until a different one comes.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/bcmwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
	"github.com/antoniocosta/unifi-openwrt/internal/mtkwifi"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

type job struct {
	what string
	fn   func(ctx context.Context)
}

// provision is one system_cfg to bring live, captured by the loop.
type provision struct {
	why       string
	systemCfg string // carries passphrases: never logged
	hash      string // short sha256 of systemCfg, for logs
	sum       [sha256.Size]byte
	// cfgVersion: the controller's cfgversion when this system_cfg was
	// captured; acknowledged once it is live (cfgack.go)
	cfgVersion string
	blocked    []string
}

// workerState belongs to the worker goroutine.
type workerState struct {
	enforced    bool             // decosys.Enforce succeeded once
	hold        string           // why the last Enforce said hands off Wi-Fi ("" = none): a rebuild or upgrade in flight
	pending     *provision       // waits for enforced (and no hold)
	applied     *bcmwifi.Desired // live and verified (apply=true only); schedule-off SSIDs disabled
	verifyFails int

	full     *bcmwifi.Desired // the controller's Wi-Fi, schedules not applied
	schedOff map[string]bool  // WLAN ids off by their schedule now
	users    []translate.User // site device logins (users.N) to keep in /etc
	usersSet bool             // users came from a system_cfg
	clean    int              // Enforce passes in a row that changed nothing
	since    time.Time        // first Enforce (fast phase start)
	steady   bool             // the fast Enforce phase is over

	counts    map[string]int       // the agent's own R10 tallies (bcmwifi Tick and friends)
	checked   time.Time            // last self-check summary
	lastSum   string               // last summary logged
	evented   map[string]time.Time // foreign finding -> when it last went to the event ring
	tickFails int                  // bcmwifi.Tick errors in a row (logged on change)

	dfsReset   *translate.DailyTime // the controller's dfs-reset cron time (dfs.go); nil = none
	dfsResetAt time.Time            // the last dfs-reset check
}

// rebuildWarning starts the decosys Report warning for a TP-Link Wi-Fi
// rebuild in flight (repacd restart, /sbin/wifi; decosys plan.go). Enforce
// reports it and does not interrupt it; while it runs, the rebuild restarts
// TP-Link's hostapd and raises its BSSes, so the agent neither applies nor
// rolls back (TestRebuildInFlightDefersApply).
const rebuildWarning = decosys.WarnRebuild

// holdReason is why Wi-Fi must be left alone now ("" = it need not): a
// TP-Link Wi-Fi rebuild or a firmware upgrade in flight (R17). The rc.d
// boot chain holds only while it is plausibly still booting (the gate's
// give-up uptime): a boot script left running for good must not keep the
// controller's Wi-Fi off forever.
func holdReason(rep decosys.Report, uptime float64) string {
	g := rep.Guard
	switch {
	case len(g.Upgrade) > 0:
		return "a TP-Link firmware upgrade is in flight (" + g.Upgrade[0] + ")"
	case len(g.Rebuild) > 0:
		return "a TP-Link Wi-Fi rebuild is still running (" + g.Rebuild[0] + ")"
	case len(g.Boot) > 0 && uptime < gateGiveUp:
		return "TP-Link's boot scripts are still running (" + g.Boot[0] + ")"
	}
	for _, w := range rep.Warnings {
		switch {
		case strings.HasPrefix(w, decosys.WarnUpgrade):
			return "a TP-Link firmware upgrade is in flight (" + w + ")"
		case strings.HasPrefix(w, decosys.WarnRebuild):
			return "a TP-Link Wi-Fi rebuild is still running (" + w + ")"
		}
	}
	return ""
}

// submit queues a Wi-Fi job. Jobs run one at a time, in order.
func (a *agent) submit(what string, fn func(ctx context.Context)) {
	select {
	case a.jobs <- job{what, fn}:
	default:
		a.logf("wifi worker: queue full, dropped %s", what)
	}
}

func (a *agent) workerLoop(ctx context.Context) {
	// R1: right after the boot gate Enforce runs every fastEnforce until
	// two passes in a row changed nothing and fastMin has passed (late
	// TP-Link starters are caught within seconds), then every enforceEvery.
	tick := time.NewTicker(min(a.t.fastEnforce, a.t.enforceEvery))
	defer tick.Stop()
	sched := time.NewTicker(a.t.scheduleEvery)
	defer sched.Stop()
	a.worker.since = time.Now()
	if ctx.Err() == nil {
		a.runJob(ctx, job{"enforce", a.tick})
	}
	for a.takeover.Load() {
		if !a.worker.steady && a.worker.clean >= 2 && time.Since(a.worker.since) >= a.t.fastMin {
			a.worker.steady = true
			tick.Reset(a.t.enforceEvery)
			a.logf("decosys: TP-Link stays stopped: Enforce every %s from now on", a.t.enforceEvery)
		}
		// select picks at random among ready cases: after SIGTERM a queued
		// job (an apply) or a due tick must not start (TestWorkerNoJobAfterSIGTERM).
		select {
		case <-ctx.Done():
			return
		case j := <-a.jobs:
			if ctx.Err() != nil {
				a.logf("wifi worker: stopping, %s not started", j.what)
				return
			}
			a.runJob(ctx, j)
		case <-tick.C:
			if ctx.Err() != nil {
				return
			}
			a.runJob(ctx, job{"enforce", a.tick})
		case <-sched.C:
			if ctx.Err() != nil {
				return
			}
			a.runJob(ctx, job{"schedules", func(ctx context.Context) {
				a.scheduleTick(ctx)
				a.dfsResetTick(ctx) // the controller's nightly dfs-reset (dfs.go)
			}})
		}
	}
	a.logf("wifi worker: stopped (observe mode)")
}

// runJob runs one job with a context SIGTERM does not cancel: an apply
// that is under way finishes (or rolls back) rather than being cut in the
// middle, which could leave neither hostapd running.
func (a *agent) runJob(ctx context.Context, j job) {
	if !a.takeover.Load() {
		a.logf("observe mode: %s not done", j.what)
		return
	}
	jctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.t.jobTimeout)
	defer cancel()
	if aliveJob(j.what) {
		a.markAlive("running", true, j.what)
		defer a.markAlive("running", true, "")
	} else {
		// a routine tick: marked only once it changes the unit (aliveLazy)
		lz := &aliveLazy{what: j.what}
		jctx = context.WithValue(jctx, aliveLazyKey{}, lz)
		defer func() {
			if lz.marked.Load() {
				a.markAlive("running", true, "")
			}
		}()
	}
	j.fn(jctx)
}

// startupJobs re-applies what the controller set, after an agent or unit
// restart (takeover mode; the first Enforce runs before them).
func (a *agent) startupJobs() {
	if !a.x.S.Adopted {
		return
	}
	blocked := append([]string{}, a.x.S.Blocked...)
	a.submit("blocked list", func(ctx context.Context) { a.setBlocked(ctx, blocked) })
	if strings.Contains(a.x.S.MgmtCfg, "led_enabled=") {
		mode := map[bool]string{true: bcmwifi.LEDOn, false: bcmwifi.LEDOff}[a.x.S.LED]
		a.submit("led "+mode, func(ctx context.Context) { a.led(ctx, mode) })
	}
	if a.x.S.Locating {
		a.submit("locate", func(ctx context.Context) { a.led(ctx, bcmwifi.LEDLocate) })
	}
	for _, mac := range a.authorizedGuests(time.Now()) {
		a.submit("guest-auth "+mac, func(ctx context.Context) { a.guestAuth(ctx, mac, true) })
	}
	a.pushClientRates("startup") // also clears a list left in RunDir
	a.provisionIfNew("startup")
}

// tick is the periodic takeover enforcement and Wi-Fi health check.
// Order: the inbound fence, decosys.Enforce (which also re-asserts the R8a
// address watch, the R11 reset-button wrapper, the crontab invariant and
// the TP-Link QoS removal, and holds while an upgrade is in flight),
// egress, the site users, the self-check; then Wi-Fi: a pending provision,
// else bcmwifi.Tick (non-disruptive repairs, each followed by a flow-cache
// flush inside bcmwifi) and the health check.
func (a *agent) tick(ctx context.Context) {
	w := &a.worker
	if err := a.sys.Ingress(ctx, true); err != nil {
		a.logf("decosys: inbound fence: %v", err)
	}
	rep, err := a.sys.Enforce(ctx)
	if rep.Changed() {
		a.logf("decosys: enforce: %d step(s)", len(rep.Steps))
		w.clean = 0
	} else if err == nil {
		w.clean++
	}
	for _, s := range rep.Warnings {
		a.logf("decosys: warning: %s", s)
	}
	a.foreign(rep.Foreign)
	up, _ := readUptime(a.o.root)
	hold := holdReason(rep, up)
	if hold != w.hold {
		if hold != "" {
			a.logf("decosys: %s: no Wi-Fi change until it has finished", hold)
		} else if w.hold != "" {
			a.logf("decosys: nothing in flight any more: Wi-Fi changes resume")
		}
		w.hold = hold
	}
	a.scanHold.Store(hold)
	switch {
	case err != nil:
		a.logf("decosys: enforce: %v", err)
	case hold != "":
	case !w.enforced:
		w.enforced = true
		a.logf("decosys: TP-Link services stopped (awnd, acsd2 and the rest); the agent may now own Wi-Fi")
	}
	if a.cfg.Egress {
		if err := a.sys.Egress(ctx, true); err != nil {
			a.logf("decosys: egress: %v", err)
		}
	}
	if w.usersSet {
		a.syncUsers(w.users, false)
	}
	defer a.selfCheck()
	if hold != "" {
		return // neither apply nor repair nor health rollback while TP-Link rebuilds or flashes
	}
	if w.enforced && w.pending != nil {
		pv := *w.pending
		w.pending = nil
		a.provision(ctx, pv)
		return
	}
	a.wifiTick(ctx)
	a.health(ctx)
	if a.takeover.Load() {
		a.portsApply(ctx, "tick") // a port someone moved is put back (ports.go)
	}
}

// wifiTick runs bcmwifi.Tick while the agent's Wi-Fi is live: driver MAC
// filters, WDS peers, bridge membership, unused vifs, guest chains and rate
// limits are repaired in place. Drift that needs a hostapd restart is left
// to the health check right after (Verify, then Rollback to last-good).
func (a *agent) wifiTick(ctx context.Context) {
	w := &a.worker
	if w.applied == nil {
		return
	}
	r, err := a.wifi.Tick(ctx)
	if err != nil {
		if w.tickFails++; w.tickFails == 1 {
			a.logf("wifi: tick: %v", err)
		}
		return
	}
	if w.tickFails > 0 {
		a.logf("wifi: tick works again (after %d failure(s))", w.tickFails)
		w.tickFails = 0
	}
	a.count("wifi-foreign", len(r.Foreign))
	a.count("wifi-repair", r.Steps)
	a.count("rate-limit", r.RateLimitChanges)
	a.count("wifi-11k-neighbor", r.NeighborChanges)
	a.radarIn(r.Radar) // EVT_AP_RadarDetected (dfs.go)
	for _, p := range r.Problems {
		a.logf("wifi: tick: %s", p)
	}
	if r.NeedsApply {
		a.count("wifi-needs-apply", 1)
		a.logf("wifi: tick: the live Wi-Fi drifted in a way only an apply fixes: left to the health check")
	}
	if r.Steps > 0 || r.RateLimitChanges > 0 {
		a.o.col.Invalidate()
	}
	a.ftSync(ctx) // FT-SAE peers the last sync could not add (ftsae.go)
}

func (a *agent) count(kind string, n int) {
	if n <= 0 {
		return
	}
	if a.worker.counts == nil {
		a.worker.counts = map[string]int{}
	}
	a.worker.counts[kind] += n
}

// provision brings a system_cfg live through bcmwifi.
func (a *agent) provision(ctx context.Context, pv provision) {
	w := &a.worker
	full, in := a.logIntent(pv)
	if !w.enforced || w.hold != "" {
		w.pending = &pv
		a.logf("wifi: system_cfg %s waits for decosys.Enforce to succeed (and any TP-Link Wi-Fi rebuild or upgrade to finish) before any chanspec is pinned", pv.hash)
		return
	}
	// LAN ports (ports.go): their VLAN bridges are kept through the Wi-Fi
	// apply, and the ports follow the switch section once the Wi-Fi is done
	a.portsPrepare(pv)
	defer a.portsApply(ctx, "system_cfg "+pv.hash)
	w.users, w.usersSet = in.Users, true
	w.dfsReset = in.DFSReset
	a.syncUsers(w.users, true)
	full = a.radsecProvision(ctx, full, in) // RADIUS over TLS through the local proxy (radsec.go)
	// WLAN schedules: the SSIDs off now are applied disabled (schedule.go).
	off := scheduleOff(full, a.o.now())
	d := withSSIDsOff(full, off)
	a.setBlocked(ctx, pv.blocked) // stored first, so the plan folds it in
	p, err := a.wifi.Plan(ctx, d)
	if err != nil {
		a.logf("wifi: plan for system_cfg %s: %v (nothing changed)", pv.hash, err)
		a.cfgDone(pv, false)
		return
	}
	for _, n := range p.Notes {
		a.logf("wifi: note: %s", n)
	}
	// the auto channel rides a radio restart the plan makes anyway
	// (autochan.go)
	if p.RadioRestart() {
		if pd, notes := a.autoChannels(ctx, d, in, p.RadioRestartBand); !reflect.DeepEqual(pd.Radios, d.Radios) {
			for _, n := range notes {
				a.logf("wifi: %s", n)
			}
			if pp, err := a.wifi.Plan(ctx, pd); err == nil {
				pf, _ := a.autoChannels(ctx, full, in, p.RadioRestartBand) // the same picks (autoPick)
				d, full, p = pd, pf, pp
			} else {
				a.logf("wifi: auto channel: plan: %v (the live channels kept)", err)
			}
		}
	}
	if p.Empty() {
		a.logf("wifi: system_cfg %s (%s) is already live", pv.hash, pv.why)
		a.wifiLive(full, d, off)
		a.cfgDone(pv, true)
		return
	}
	a.logf("wifi: applying system_cfg %s (%s): %d step(s)", pv.hash, pv.why, len(p.Steps))
	prev := w.applied
	err = a.wifiChange(func() error { return a.wifi.Apply(ctx, p) })
	if errors.Is(err, bcmwifi.ErrDesiredFailed) {
		// bcmwifi remembers (in memory) the last Desired that failed and
		// was rolled back, and refuses that identical Desired without
		// touching the unit. Nothing changed, so the live Wi-Fi and its
		// health check stay as they are, and there is no retry: the next
		// attempt comes with a different Desired from the controller (or a
		// restart of the agent, bounded by the crash-loop guard).
		a.logf("wifi: system_cfg %s (%s) asks for the same Wi-Fi that failed to apply before: not retried until the controller sends a different one (%v)", pv.hash, pv.why, err)
		a.cfgDone(pv, false)
		return
	}
	a.o.col.Invalidate()
	if err != nil {
		a.wifiFailed(ctx, "apply", err)
		if a.takeover.Load() && prev != nil {
			// Still owned: bcmwifi rolled back to its last-good, which is
			// prev (the verified apply that made it live saved it). Keep
			// the health check on it, or a later fault (our hostapd gone)
			// would never be rolled back (TestApplyErrorKeepsHealthCheck).
			w.applied = prev
		}
		a.cfgDone(pv, false)
		return
	}
	a.logf("wifi: system_cfg %s is live", pv.hash)
	a.wifiLive(full, d, off)
	a.setBlocked(ctx, pv.blocked)
	a.cfgDone(pv, true)
}

// wifiLive records a live provision: d (full with the schedule-off SSIDs
// disabled) was applied, and the steering policy follows it.
func (a *agent) wifiLive(full, d bcmwifi.Desired, off map[string]bool) {
	w := &a.worker
	w.full, w.schedOff = &full, off
	a.markApplied(d)
	a.policy.Store(policyFrom(full))
}

func (a *agent) markApplied(d bcmwifi.Desired) {
	w := &a.worker
	w.verifyFails = 0
	if a.cfg.Apply {
		w.applied = &d
	}
	a.ftKick() // FT-SAE: announce the new key holders, add peers live (ftsae.go)
}

// health verifies the applied Wi-Fi; two failed checks in a row roll back.
func (a *agent) health(ctx context.Context) {
	w := &a.worker
	if w.applied == nil {
		return
	}
	// Serialised with the scans (spectrum-design §8.7): `wl chanspec`
	// shows the scan channel while a scan runs. Waiting for a scan (a band
	// takes up to about 105 s) is not a health failure: when the wait runs
	// out the check is skipped and counts for nothing.
	d := *w.applied
	var err error
	wctx, cancel := context.WithTimeout(ctx, a.t.healthWait)
	werr := a.o.col.WithoutScan(wctx, func(context.Context) error {
		err = a.wifi.Verify(ctx, d)
		return nil
	})
	cancel()
	if werr != nil {
		a.logf("wifi: health check skipped: a scan was still running after %s (%v); not counted", a.t.healthWait, werr)
		return
	}
	if err == nil {
		w.verifyFails = 0
		return
	}
	w.verifyFails++
	a.logf("wifi: health check %d failed: %v", w.verifyFails, err)
	if w.verifyFails < 2 {
		return
	}
	w.verifyFails = 0
	a.event("wifi: health check failed twice: rolling back to last-good")
	err = a.wifiChange(func() error { return a.wifi.Rollback(ctx) })
	a.o.col.Invalidate()
	switch {
	case err != nil:
		a.wifiFailed(ctx, "rollback", err)
	case !a.wifiOwned():
		a.wifiFailed(ctx, "rollback", errors.New("last-good did not come up; handed back to TP-Link"))
	}
}

// wifiFailed handles an Apply or Rollback error. When Wi-Fi went back to
// TP-Link, TP-Link's services come back too and the agent observes only.
func (a *agent) wifiFailed(ctx context.Context, op string, err error) {
	w := &a.worker
	w.applied = nil
	// bcmwifi.ErrDesiredFailed never gets here: provision handles it
	// before (nothing changed, so it is no hand-back).
	if errors.Is(err, bcmwifi.ErrNoBaseline) || !a.wifiOwned() {
		a.dropToObserve(ctx, fmt.Sprintf("%s: %v", op, err))
		return
	}
	a.logf("wifi: %s failed and Wi-Fi was rolled back to last-good (the agent still owns it): %v", op, err)
}

// wifiOwned reports whether the agent's hostapd confs exist: bcmwifi
// writes RunDir/hapd-wlN.conf when it takes a radio and removes them when
// it hands Wi-Fi back.
// TODO(bcmwifi-owned): use an exported bcmwifi ownership query once there
// is one; this reads bcmwifi's documented file layout.
func (a *agent) wifiOwned() bool {
	if o, ok := a.wifi.(interface{ Owned() bool }); ok {
		return o.Owned()
	}
	for _, p := range []string{"wl0", "wl1"} {
		if _, err := os.Stat(a.dev(filepath.Join(a.o.runDir, "hapd-"+p+".conf"))); err == nil {
			return true
		}
	}
	return false
}

// followRestarts keeps the collector's driver reads away from the Wi-Fi
// applier's radio restarts and their settle time (jio-mtk: mtkwifi
// restartgate.go): the inform loop, the live view and the home listen
// serve the last reading meanwhile, never probing a driver mid-restart and
// never waiting for the apply.
func (a *agent) followRestarts() {
	g, ok := a.wifi.(mtkwifi.RestartGate)
	if !ok {
		return
	}
	if c, ok := a.o.col.(interface{ FollowRestarts(mtkwifi.RestartGate) }); ok {
		c.FollowRestarts(g)
	}
}

// dropToObserve gives the unit back to TP-Link and stops changing it. The
// marker next to the config (/tp_data, persistent) keeps a restarted agent
// in observe mode, across reboots too, until it is removed (boot.go).
func (a *agent) dropToObserve(ctx context.Context, why string) {
	m := filepath.Join(a.o.base, observeMarker)
	a.event(fmt.Sprintf("!!!!! Wi-Fi is back with TP-Link (%s): restoring TP-Link's services and dropping to OBSERVE mode until %s is removed !!!!!", why, m))
	a.takeover.Store(false)
	a.portsRestore(ctx) // the LAN ports back on the untagged LAN (ports.go)
	a.siteApply()       // site SSH logins end with the takeover (sitessh.go)
	a.worker.applied, a.worker.pending, a.worker.full = nil, nil, nil
	a.ftDrop() // no more FT-SAE key holders to announce (ftsae.go)
	a.policy.Store(nil)
	a.radsecStop() // TP-Link's hostapd does not use the RadSec proxy (radsec.go)
	// Restore also puts TP-Link's reset-button handler and QoS back and
	// removes the inbound fence: the unit is TP-Link's again.
	if err := a.sys.Restore(ctx); err != nil {
		a.logf("decosys: restore: %v (reboot the unit for a clean stock state)", err)
	}
	// jio-mtk: the vendor daemons that set the front LED stay stopped, and
	// observe mode runs no LED job, so a Locate blink would never end: the
	// LED goes back to the controller's last led_enabled (led.go)
	if a.cfg.jio() {
		a.led(ctx, bcmwifi.LEDLocateOff)
	}
	// the hand-back turned the flow cache on; this retries a failure
	a.restoreFlowCache(ctx, a.wifi)
	// Restore put the loop guard's ports back (and removed the record):
	// the loop goroutine forgets them at its next reading
	a.loopReload.Store(true)
	if err := writeMarker(a.dev(m), why, a.o.now()); err != nil {
		a.logf("writing %s: %v (a restarted agent would take over again)", m, err)
	}
}

func (a *agent) setBlocked(ctx context.Context, macs []string) {
	if err := a.wifi.SetBlocked(ctx, macs); err != nil {
		a.logf("wifi: blocked list (%d): %v", len(macs), err)
	}
}

func (a *agent) led(ctx context.Context, mode string) {
	if err := a.wifi.LED(ctx, mode); err != nil {
		a.logf("led %s: %v", mode, err)
	}
}

// logIntent logs the controller's plan (masked) and returns it as a
// bcmwifi.Desired, with the intent it came from.
func (a *agent) logIntent(pv provision) (bcmwifi.Desired, translate.Intent) {
	in, notes := translate.IntentFromCfg(pv.systemCfg)
	d, dn := desiredFrom(in)
	if a.cfg.jio() {
		var mn []string
		d, mn = jioMinRates(d, a.cfg.MinRates)
		dn = append(dn, mn...)
	}
	var cn []string
	d, cn = withDriverCountry(d, a.cfg.DriverCountry)
	dn = append(dn, cn...)
	gw, _ := a.topo.gwIP.Load().(string)
	gwMAC, _ := a.topo.gwMAC.Load().(string)
	var gn []string
	d.Guest, gn = guestPolicy(d, translate.GuestPolicy(translate.ParseCfg(pv.systemCfg)), gwMAC, gw)
	a.logf("wifi: controller plan from system_cfg %s (%s): %v", pv.hash, pv.why, in)
	for _, n := range append(append(notes, dn...), gn...) {
		if a.portsOn() && strings.HasPrefix(n, "switch: ") {
			continue // the switch section is the ports' (ports.go)
		}
		a.logf("wifi: not carried: %s", n)
	}
	return d, in
}

// guestPolicy is bcmwifi's guest isolation for d's guest SSIDs (nil when
// there are none): the controller's restricted and pre-allowed ranges and
// portal, plus what only the unit knows, the gateway's MAC and IP (guests
// may reach no other LAN host; DNS goes to the gateway). Without the
// gateway's MAC bcmwifi cannot isolate guests and does not serve their SSIDs
// (it fails closed), so the policy is left out with a note.
func guestPolicy(d bcmwifi.Desired, g translate.Guest, gwMAC, gwIP string) (*bcmwifi.GuestPolicy, []string) {
	guests := false
	for _, s := range d.SSIDs {
		guests = guests || s.Guest && s.Enabled
	}
	if !guests {
		return nil, nil
	}
	if gwMAC == "" || gwIP == "" {
		return nil, []string{"guest SSIDs: the gateway's MAC/IP is not known yet (no ARP entry): not served until a later provision"}
	}
	p := &bcmwifi.GuestPolicy{GatewayMAC: gwMAC, GatewayIP: gwIP,
		Restricted: append([]string{}, g.Restricted...), PreAllow: append([]string{}, g.PreAllow...), Portal: g.Portal}
	if g.Portal {
		if ip := net.ParseIP(g.PortalHost); ip != nil && ip.To4() != nil {
			p.PortalHost = g.PortalHost
		}
	}
	var notes []string
	if g.Portal {
		notes = append(notes, "guest portal: no HTTP redirect on the unit (ebtables has no redirect target); unauthorised guests reach DHCP, DNS, the pre-allow list and the portal host only")
	}
	return p, notes
}

// desiredFrom maps the controller's intent onto bcmwifi's Desired. The notes
// list what bcmwifi cannot take (never secrets).
func desiredFrom(in translate.Intent) (bcmwifi.Desired, []string) {
	var notes []string
	d := bcmwifi.Desired{Country: in.Country, Radios: map[string]bcmwifi.Radio{}}
	for band, r := range in.Radios {
		if band != "ng" && band != "na" {
			notes = append(notes, "radio "+band+": the unit has no such radio")
			continue
		}
		d.Radios[band] = bcmwifi.Radio{Enabled: r.Enabled, Channel: r.Channel, Width: r.Width,
			TxPowerMode: r.TxPowerMode, TxPower: r.TxPower, MinRSSI: r.MinRSSI,
			// the controller's limit is per radio, bcmwifi's per BSS: a
			// radio with several SSIDs may take more clients in total
			MaxClients: r.MaxClients, BandSteer: r.BandSteer}
	}
	for _, wl := range in.WLANs {
		s := bcmwifi.SSID{ID: wl.ID, SSID: wl.SSID, Enabled: wl.Enabled, Hidden: wl.Hidden, Guest: wl.Guest,
			Security: wl.Security, Passphrase: wl.Passphrase, PMF: wl.PMF, GroupRekey: wl.GroupRekey,
			VLAN: wl.VLAN, Isolation: wl.Isolation, FT: wl.FT, BSSTransition: wl.BSSTransition, RRM: wl.RRM,
			// 802.11r: FT-SAE with the WLAN's iapp_key, the controller's MDID
			// when it sends one (bcmwifi ftsae.go)
			FTSAE: wl.FTSAE, FTKey: wl.FTKey, FTOverDS: wl.FTOverDS, MobilityDomain: wl.MobilityDomain,
			UAPSD: wl.UAPSD, ProxyARP: wl.ProxyARP, MulticastToUnicast: wl.MulticastToUnicast,
			DTIM: wl.DTIM, MinRateKbps: wl.MinRateKbps, Schedule: wl.Schedule,
			NoBSSLoad:   wl.NoBSSLoad,   // per radio in bcmwifi (parity.go)
			NoBGAFilter: wl.NoBGAFilter} // bcmwifi bga.go
		s.MinRateOpts = minRateOpts(wl.MinRateOpts)
		for band, b := range wl.PerBand {
			if s.PerBand == nil {
				s.PerBand = map[string]bcmwifi.BandSettings{}
			}
			s.PerBand[band] = bcmwifi.BandSettings{Security: b.Security, PMF: b.PMF, FT: b.FT, FTSAE: b.FTSAE,
				FTOverDS: b.FTOverDS, MobilityDomain: b.MobilityDomain, BSSTransition: b.BSSTransition, RRM: b.RRM,
				UAPSD: b.UAPSD, ProxyARP: b.ProxyARP, MulticastToUnicast: b.MulticastToUnicast, Hidden: b.Hidden,
				Isolation: b.Isolation, GroupRekey: b.GroupRekey}
		}
		for _, b := range wl.Bands {
			if b == "ng" || b == "na" {
				s.Bands = append(s.Bands, b)
			}
		}
		s.RoamAssist = wl.RoamAssist // agent-side (roaming.go)
		s.No2GHz = wl.No2GHz         // agent-side (no2ghz.go)
		if wl.MACFilter != nil {
			s.MACFilter = &bcmwifi.MACFilter{Policy: wl.MACFilter.Policy, MACs: append([]string{}, wl.MACFilter.MACs...)}
		}
		s.PSKs = desiredPSKs(wl.PSKs) // private pre-shared keys (ppsk.go)
		// Hotspot 2.0 (bcmwifi/hs20.go); nil = off
		s.Hotspot2 = wl.Hotspot2.Clone()
		if wl.RateLimit != nil {
			s.RateLimit = &bcmwifi.RateLimit{DownKbps: wl.RateLimit.DownKbps, UpKbps: wl.RateLimit.UpKbps}
		}
		if r := wl.Radius; r != nil {
			s.Radius = &bcmwifi.Radius{NASID: r.NASID, FilterID: r.FilterID}
			for _, x := range r.Auth {
				s.Radius.Auth = append(s.Radius.Auth, bcmwifi.RadiusServer{IP: x.Host, Port: x.Port, Secret: x.Secret})
			}
			for _, x := range r.Acct {
				s.Radius.Acct = append(s.Radius.Acct, bcmwifi.RadiusServer{IP: x.Host, Port: x.Port, Secret: x.Secret})
			}
			// RADIUS MAC authentication: bcmwifi writes macaddr_acl=2 and
			// refuses the SSID (never serves it open) when no usable auth
			// server is given; a MAC format hostapd 2.9 cannot select is
			// noted by bcmwifi's Plan. The capability bit
			// (models.WifiCapRadiusMACAuth) is still not claimed: whether
			// hostapd's RADIUS ACL query runs at all with the Broadcom driver
			// is untested on a unit.
			s.Radius.MACAuth, s.Radius.MACFormat = r.MACAuth, r.MACFormat
			// RadSec servers are reachable only through the agent's proxy:
			// held off here (never sent plain UDP RADIUS), radsecRoute
			// (radsec.go) turns the WLAN back on once they are routed
			if hasRadSec(r) {
				s.Enabled = false
				notes = append(notes, fmt.Sprintf("wlan %s: %s", wl.ID, radsecHeldNote))
			}
		}
		d.SSIDs = append(d.SSIDs, s)
	}
	// in.Syslog: forwarded by the agent itself (syslogfwd.go), not Wi-Fi
	if in.LED != nil {
		notes = append(notes, "ledbar.status: the LED follows mgmt_cfg led_enabled")
	}
	return d, notes
}

// withDriverCountry applies the driver_country override. A 5 GHz DFS
// channel (52-144) under the override is likely outside its table (the
// X20's US/0 allows 36-48 and 149-165 only, live-facts 2026-11-20), so the
// controller's channel would be refused and the radio left on auto: the
// note says to drop the override (India runs as IN/288, which has them).
func withDriverCountry(d bcmwifi.Desired, override string) (bcmwifi.Desired, []string) {
	dc := strings.ToUpper(strings.TrimSpace(override))
	if dc == "" || strings.EqualFold(dc, d.Country) {
		return d, nil
	}
	notes := []string{fmt.Sprintf("country %s: the radios run as %s (driver_country)", d.Country, dc)}
	if r, ok := d.Radios["na"]; ok && r.Enabled && r.Channel >= 52 && r.Channel <= 144 {
		notes = append(notes, fmt.Sprintf("5 GHz DFS channel %d under driver_country %s: refused unless that table has it; remove driver_country to serve it in %s", r.Channel, dc, d.Country))
	}
	d.Country = dc
	return d, notes
}
