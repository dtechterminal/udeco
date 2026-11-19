// SPDX-License-Identifier: GPL-2.0-or-later

package main

// LAN ports (platform jio-mtk, model UHDIW): the JCOW414's switch ports are
// reported as a UAP-IW-HD's (internal/jioports: front ports 1-3 = the
// unit's ports 1-3, UniFi port 4 absent, rear port 5 = the unit's port 4,
// the uplink), and in takeover mode the controller's port VLANs
// (system_cfg switch.*) are applied to the ports it may change: 2 and 3,
// and 1 only with ports_unlocked. The uplink never changes beyond the VLAN
// devices the VLAN SSIDs already put on it.
//
// The switch section arrives only once "Enable Port VLAN" is on in the
// device's settings, which the controller offers because the agent claims
// fw_caps QCA switch and OWRT switch (models.FWCapQCASwitch,
// FWCapOWRTSwitch) in takeover mode.
//
// The port monitor (there is no remote power control, and telnet over the
// LAN is the only way in, so a port change that cuts the unit off must
// undo itself):
//
//   - confirm or revert: a change Apply makes to a port's live setting
//     (to a VLAN, back to the plain LAN, or onto the LAN by a failed
//     change's rollback) is pending until an inform that STARTED after the
//     change got a valid reply from the controller. The change wakes the
//     inform loop, and while one is pending a failing inform is retried
//     every portsRetry (15 s) at most instead of backing off further. With
//     no confirmation within ports_confirm_s (90 s) the ports of that
//     change go back to the settings they had before, the setting is
//     marked failed (jioports: not applied again until the controller sends
//     another one for the port) and "EVENT: PORTS REVERTED" goes to the
//     event ring;
//   - controller loss: with no inform answered for ports_loss_s (300 s)
//     every port the agent may change goes back on the plain LAN (the
//     uplink and locked ports untouched) and port settings are held off
//     until an inform is answered again; the controller's settings then
//     apply again, each through the confirm window. A setting the loss
//     watchdog takes off twice in a row is marked failed; "in a row" ends
//     once informs have been answered for 2 x ports_loss_s after the
//     resume (the setting kept the unit reachable: a later outage is
//     another one);
//   - startup: no port setting is applied before the first answered
//     inform; the loss watchdog covers ports a previous run left off the LAN.
//
// The monitor runs in its own goroutine (portsWatchLoop) so neither a long
// Wi-Fi job in the worker nor an inform stuck on a dead connection delays
// it. Every port change, the worker's and the monitor's, holds ports.mu
// (and each Bridger call mtkwifi's own lock, which a Wi-Fi apply holds
// while it runs); the inform loop only takes ports.w.mu, briefly, so it
// never waits on the device. Lock order: ports.mu, then ports.w.mu.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/jioports"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// portState: ctr belongs to the loop goroutine; mgr (set at setup) and
// want are used under mu (the worker and the port monitor); w under w.mu.
type portState struct {
	ctr  *jioports.Counters
	mu   sync.Mutex
	mgr  *jioports.Manager // takeover only
	want *jioports.Want    // the last system_cfg's switch section
	w    portWatch
}

// portWatch is the port monitor's state.
type portWatch struct {
	mu      sync.Mutex
	confirm time.Duration // ports_confirm_s
	loss    time.Duration // ports_loss_s
	lastOK  time.Time     // the last inform the controller answered (setup: the start)
	ok      bool          // an inform was answered since the start or the loss revert: settings may apply
	lost    bool          // the loss watchdog put the ports on the LAN: held there until an inform is answered
	resumed time.Time     // the first answered inform after the last loss revert
	pending map[int]portPending
	// lossWant: what the last loss revert took off each port
	lossWant map[int]string
}

// portPending is a port change the controller has not confirmed.
type portPending struct {
	since time.Time         // when the change finished
	want  string            // the controller's setting (marked failed on a revert)
	live  string            // what the change made live: want, or the LAN when want failed
	back  jioports.PortWant // the setting before (the revert's target)
}

const (
	defaultPortsConfirm = 90 * time.Second
	defaultPortsLoss    = 300 * time.Second
)

// portsOn reports whether the unit reports LAN ports (jio-mtk as UHDIW).
func (a *agent) portsOn() bool { return a.cfg.jio() && a.cfg.Model == "UHDIW" }

// portLocked: the uplink always, port 1 unless ports_unlocked lists it.
func (a *agent) portLocked(phys int) bool {
	if phys == jioports.UplinkPhys {
		return true
	}
	if phys != 1 {
		return false
	}
	for _, p := range a.cfg.PortsUnlocked {
		if p == phys {
			return false
		}
	}
	return true
}

// portsSetup builds the port manager (setup, takeover mode). It reports
// whether the agent applies port VLANs (the PortVLAN feature).
func (a *agent) portsSetup() bool {
	a.ports.ctr = jioports.NewCounters()
	if !a.portsOn() || !a.takeover.Load() || a.wifi == nil {
		return false
	}
	if a.modelHeld != "" {
		a.logf("ports: port VLANs are not applied: UniFi holds this unit as %s, not %s (adoptmodel.go: Forget, adopt again, restart the agent)", a.modelHeld, a.cfg.Model)
		return false
	}
	b, ok := a.wifi.(jioports.Bridger)
	if !ok {
		a.logf("ports: the Wi-Fi backend cannot bridge ports: port VLANs are not applied")
		return false
	}
	a.ports.mgr = jioports.New(jioports.Options{B: b, Unlocked: a.cfg.PortsUnlocked, DryRun: !a.cfg.Apply, Logf: a.logf,
		Uplink: func() string { u, _ := a.topo.uplinkName.Load().(string); return u }})
	a.ports.w = portWatch{confirm: a.cfg.portsConfirm(), loss: a.cfg.portsLoss(), lastOK: a.o.now(),
		pending: map[int]portPending{}, lossWant: map[int]string{}}
	var free []string
	for _, p := range jioports.LANPorts {
		if !a.portLocked(p) {
			free = append(free, fmt.Sprint(p))
		}
	}
	a.logf("ports: the controller's port VLANs apply to LAN port(s) %s (port 1 only with ports_unlocked; port 4 is the uplink); a change the controller does not confirm within %s is reverted, and with no answer from the controller for %s the ports go back on the LAN",
		strings.Join(free, ","), a.ports.w.confirm, a.ports.w.loss)
	return true
}

// portFields gives the inform the UAP-IW-HD's five ports (loop goroutine).
func (a *agent) portFields(f map[string]any, s *apstate.Snapshot) {
	macs := map[int][]map[string]any{}
	for _, p := range s.Ports {
		for _, phys := range jioports.LANPorts {
			if p.Name == jioports.Untagged(phys) && p.BridgePort > 0 {
				macs[phys] = s.PortMACs(p.BridgePort)
			}
		}
	}
	for _, phys := range jioports.LANPorts {
		if _, ok := macs[phys]; ok {
			continue
		}
		// a port on a native VLAN is in br-vN, not in the LAN bridge
		if rows, ok := jioports.VLANMACs(a.o.root, phys); ok {
			macs[phys] = rows
		}
	}
	if a.ports.ctr == nil {
		a.ports.ctr = jioports.NewCounters()
	}
	links := jioports.ReadLinks(a.o.root)
	f["port_table"] = jioports.Rows(jioports.RowsInput{Links: links, Stats: a.ports.ctr.Read(a.o.root),
		MACs: macs, Locked: a.portLocked})
	if it, ok := f["if_table"].([]map[string]any); ok && len(it) > 0 {
		it[0]["num_port"] = jioports.NumPorts
		// eth0.4.1's speed file says nothing (EINVAL): the switch's does
		if l := links[jioports.UplinkPhys]; l.Up {
			it[0]["speed"], it[0]["full_duplex"] = l.Speed, l.FullDuplex
		}
	}
	if rows, ok := f["lldp_table"].([]map[string]any); ok {
		for _, r := range rows {
			r["local_port_idx"] = jioports.UplinkIdx
		}
	}
}

// portsPrepare reads the switch section of pv and tells the Wi-Fi applier
// which VLAN bridges the ports keep, before the Wi-Fi apply (worker).
func (a *agent) portsPrepare(pv provision) {
	if a.ports.mgr == nil {
		return
	}
	a.ports.mu.Lock()
	defer a.ports.mu.Unlock()
	w, notes := jioports.FromCfg(translate.ParseCfg(pv.systemCfg))
	a.ports.want = &w
	for _, n := range notes {
		a.ports.mgr.Note(n)
	}
	a.ports.mgr.Prepare(w)
}

// portsApply makes the last switch section live (worker: after a
// provision's Wi-Fi, and at every tick, where a port someone moved is put
// back). A port that fails is put back on the LAN; the configuration is
// acknowledged all the same (the Wi-Fi decides that). Nothing is applied
// before the first answered inform or while the loss watchdog holds the
// ports on the LAN; each change waits for the controller's confirmation.
func (a *agent) portsApply(ctx context.Context, why string) {
	if a.ports.mgr == nil {
		return
	}
	a.ports.mu.Lock()
	defer a.ports.mu.Unlock()
	if a.ports.want == nil {
		return
	}
	a.ports.w.mu.Lock()
	ok, lost := a.ports.w.ok, a.ports.w.lost
	a.ports.w.mu.Unlock()
	switch {
	case lost:
		a.ports.mgr.Note("the controller is unreachable: port settings are held off (the ports stay on the LAN) until an inform reaches it")
		return
	case !ok:
		a.ports.mgr.Note("port settings wait for the first inform the controller answers")
		return
	}
	r := a.ports.mgr.Apply(ctx, *a.ports.want)
	a.portsReport(r, why)
	a.portsPending(r)
}

// portsPending starts the confirm window for the ports Apply changed
// (ports.mu held), moves back to the plain LAN included (the LAN can cut
// the unit off too: a loop through a downstream switch). A port changed
// again before it was confirmed keeps the setting it had before the first
// change as its revert target; a port back on that setting has nothing to
// confirm. A port whose change failed was rolled back onto the LAN: that
// is the change waiting, unless the LAN is where it was. A new change
// wakes the inform loop, so the confirmation comes at once.
func (a *agent) portsPending(r jioports.Report) {
	if len(r.Before) == 0 {
		return
	}
	w := &a.ports.w
	now := a.o.now()
	w.mu.Lock()
	added := false
	for _, p := range jioports.LANPorts {
		before, ok := r.Before[p]
		if !ok {
			continue
		}
		want := a.ports.want.Port(jioports.Idx(p))
		live := want.String()
		if r.Failed[p] != nil {
			live = jioports.PortWant{}.String()
		}
		pd, was := w.pending[p]
		if !was {
			pd.back = before
		}
		if pd.back.String() == live {
			delete(w.pending, p)
			continue
		}
		pd.since, pd.want, pd.live = now, want.String(), live
		w.pending[p] = pd
		added = true
		if r.Failed[p] != nil {
			a.logf("ports: port %d: %s failed and the rollback put the port on the LAN (it was %s): back to %s in %s unless an inform reaches the controller", p, pd.want, pd.back, pd.back, w.confirm)
			continue
		}
		a.logf("ports: port %d: %s is waiting for the controller: back to %s in %s unless an inform reaches the controller", p, pd.live, pd.back, w.confirm)
	}
	w.mu.Unlock()
	if added {
		a.wakeLoop()
	}
}

// portsRetry is the longest the inform loop may wait between informs
// while a port change waits for its confirmation (0: none waits), so a
// short outage does not back the informs off past the confirm window.
func (a *agent) portsRetry() time.Duration {
	if a.ports.mgr == nil {
		return 0
	}
	w := &a.ports.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.pending) == 0 {
		return 0
	}
	return a.t.portsRetry
}

// portsInformed: an inform that started at start got a valid reply (loop
// goroutine; never waits on the device). It confirms the port changes
// that finished before it started and lets port settings apply again.
func (a *agent) portsInformed(start time.Time) {
	if a.ports.mgr == nil {
		return
	}
	w := &a.ports.w
	w.mu.Lock()
	w.lastOK = a.o.now()
	for _, p := range jioports.LANPorts {
		if pd, ok := w.pending[p]; ok && start.After(pd.since) {
			delete(w.pending, p)
			a.logf("ports: port %d: %s confirmed (an inform reached the controller after the change)", p, pd.live)
		}
	}
	resume := !w.ok || w.lost
	if w.lost {
		w.resumed = w.lastOK
		a.logf("ports: informs reach the controller again: its port settings apply again, each change waiting for its confirmation")
	}
	if len(w.lossWant) > 0 && w.lastOK.Sub(w.resumed) >= 2*w.loss {
		// the settings came back and kept the unit reachable: the next
		// loss is another outage, not the same setting cutting it off
		w.lossWant = map[int]string{}
	}
	w.ok, w.lost = true, false
	w.mu.Unlock()
	if resume && a.takeover.Load() {
		a.submit("ports", func(ctx context.Context) { a.portsApply(ctx, "controller reachable") })
	}
}

// portsWatchLoop runs the port monitor every portsWatch until ctx ends or
// the agent drops to observe mode.
func (a *agent) portsWatchLoop(ctx context.Context) {
	t := time.NewTicker(a.t.portsWatch)
	defer t.Stop()
	for a.takeover.Load() {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		// like runJob: a revert under way is finished, not cut at SIGTERM
		jctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), a.t.jobTimeout)
		a.portsWatch(jctx)
		cancel()
	}
}

// portsWatch is one pass of the port monitor: the unconfirmed changes
// whose window ran out are reverted, the loss watchdog puts the ports on
// the LAN, and ports a revert could not put back are retried.
func (a *agent) portsWatch(ctx context.Context) {
	if a.ports.mgr == nil || !a.takeover.Load() {
		return
	}
	a.ports.mu.Lock()
	defer a.ports.mu.Unlock()
	m, w := a.ports.mgr, &a.ports.w
	now := a.o.now()
	w.mu.Lock()
	back, failed, was := map[int]jioports.PortWant{}, map[int]string{}, map[int]string{}
	for p, pd := range w.pending {
		if now.Sub(pd.since) >= w.confirm {
			back[p], failed[p], was[p] = pd.back, pd.want, pd.live
			delete(w.pending, p)
		}
	}
	down := now.Sub(w.lastOK)
	loss := !w.lost && down >= w.loss
	lost := w.lost
	w.mu.Unlock()

	if len(back) > 0 {
		r := m.Revert(ctx, back, failed)
		var what []string
		for _, p := range jioports.LANPorts {
			if b, ok := back[p]; ok {
				what = append(what, fmt.Sprintf("port %d %s -> %s", p, was[p], b))
			}
		}
		a.event(fmt.Sprintf("PORTS REVERTED (no inform reached the controller within %s of the change): %s; not applied again until the controller sends another setting for the port",
			w.confirm, strings.Join(what, ", ")))
		a.portsFailed(r, "reverted: not confirmed by the controller")
	}
	switch {
	case loss:
		a.portsLoss(ctx, down)
	case lost:
		// held on the LAN: a port that did not get there is retried
		if off := m.OffLAN(); len(off) > 0 {
			r := m.Restore(ctx)
			for _, p := range off {
				if err := r.Failed[p]; err != nil {
					m.Note(fmt.Sprintf("port %d is not on the LAN: %v (retried every %s)", p, err, a.t.portsWatch))
				}
			}
			r.Failed = nil // noted above, not an event every pass
			a.portsLog(r, "controller unreachable")
		}
	}
	a.portsLog(m.Settle(ctx), "put back")
}

// portsLoss: no inform has been answered for down (ports.mu held). Every
// port the agent may change goes back on the plain LAN and the settings
// are held off until an inform is answered.
func (a *agent) portsLoss(ctx context.Context, down time.Duration) {
	m, w := a.ports.mgr, &a.ports.w
	off := m.OffLAN()
	took := map[int]string{}
	for _, p := range off {
		if a.ports.want != nil && !a.ports.want.Port(jioports.Idx(p)).Default() {
			took[p] = a.ports.want.Port(jioports.Idx(p)).String()
		}
	}
	w.mu.Lock()
	w.lost = true
	prev := w.lossWant
	w.lossWant = took
	w.pending = map[int]portPending{} // the loss revert takes them off the LAN's way
	w.mu.Unlock()
	if len(off) == 0 {
		a.logf("ports: no inform has reached the controller for %s: port settings are held off until one does (every port is on the LAN)", down.Round(time.Second))
		return
	}
	r := m.Restore(ctx)
	var what, twice []string
	for _, p := range off {
		what = append(what, fmt.Sprintf("port %d", p))
		if want, ok := took[p]; ok && prev[p] == want {
			m.MarkFailed(p, want)
			twice = append(twice, fmt.Sprintf("port %d %s", p, want))
		}
	}
	msg := fmt.Sprintf("PORTS REVERTED (controller unreachable for %s): %s back on the untagged LAN; port settings held off until an inform reaches the controller",
		down.Round(time.Second), strings.Join(what, ", "))
	if len(twice) > 0 {
		msg += "; taken off twice in a row, not applied again until the controller sends another setting: " + strings.Join(twice, ", ")
	}
	a.event(msg)
	a.portsFailed(r, "controller unreachable")
}

// portsFailed logs a revert's report (ports.mu held): a port it could not
// put back is an event once; the monitor's next passes retry it.
func (a *agent) portsFailed(r jioports.Report, why string) {
	for _, p := range jioports.LANPorts {
		if err := r.Failed[p]; err != nil {
			a.event(fmt.Sprintf("ports: port %d: putting it back failed: %v (retried every %s)", p, err, a.t.portsWatch))
		}
	}
	r.Failed = nil
	a.portsLog(r, why)
}

// portsReport logs an Apply or Restore and counts its steps (worker).
func (a *agent) portsReport(r jioports.Report, why string) {
	a.portsLog(r, why)
	if r.Steps > 0 {
		a.count("port-change", r.Steps)
	}
}

// portsLog logs a port report (ports.mu held): notes once, each changed
// port, and each failure as an event.
func (a *agent) portsLog(r jioports.Report, why string) {
	for _, n := range r.Notes {
		a.ports.mgr.Note(n)
	}
	var ps []int
	for p := range r.Ports {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	for _, p := range ps {
		a.logf("ports: port %d (UniFi port %d) is %s (%s)", p, jioports.Idx(p), r.Ports[p], why)
	}
	ps = ps[:0]
	for p := range r.Failed {
		ps = append(ps, p)
	}
	sort.Ints(ps)
	for _, p := range ps {
		a.event(fmt.Sprintf("ports: port %d: %v: put back on the untagged LAN", p, r.Failed[p]))
	}
}

// portsRestore puts the ports the controller may change back on the
// untagged LAN (the agent hands the unit back: dropToObserve).
func (a *agent) portsRestore(ctx context.Context) {
	if a.ports.mgr == nil {
		return
	}
	a.ports.mu.Lock()
	defer a.ports.mu.Unlock()
	r := a.ports.mgr.Restore(ctx)
	a.portsReport(r, "handed back")
	a.ports.want = nil
	a.ports.w.mu.Lock()
	a.ports.w.pending = map[int]portPending{}
	a.ports.w.mu.Unlock()
}
