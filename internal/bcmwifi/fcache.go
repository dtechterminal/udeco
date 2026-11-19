// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
)

// Broadcom flow cache (interference audit D1, requirement R21).
//
// The X20's flow cache (and Archer HW forwarding) carries established flows
// past the bridge, ebtables and qdiscs. A flow learnt before a datapath change
// keeps its old path until it idles out, so every change the agent makes to
// bridges, VLAN devices, ebtables, tc or the block list is followed by a
// flush. `fc` usage on .205 (read 2026-11-18):
//
//	fc flush [ --hw ]
//	   [ --if <interface> ] | [ --flow <flowid> ] | [ <--mac|--dstmac|--srcmac> <macaddr> ]
//
// and /proc/fcache/brlist lists the bridged flows, MACs as <aa:bb:..>,
// tx_dev last.

// FlowScope selects the flows FlushFlows removes. The zero value flushes the
// whole cache.
type FlowScope struct {
	If  string // flows through this interface (fc flush --if)
	MAC string // flows from or to this station (fc flush --mac)
}

func (s FlowScope) argv() []string {
	switch {
	case s.MAC != "":
		return []string{"fc", "flush", "--mac", s.MAC}
	case s.If != "":
		return []string{"fc", "flush", "--if", s.If}
	}
	return []string{"fc", "flush"}
}

// flushStep is the plan step that flushes the whole cache after the plan's
// datapath changes. It is optional: a missing fc must not fail an apply.
func flushStep() Step {
	s := cmdStep("flush flow cache (audit R21)", "fc", "flush")
	s.Optional = true
	return s
}

// datapathStep reports a step after which established flows must be flushed:
// a bridge port change, a bridge or VLAN device created or deleted, or an
// ebtables change.
func datapathStep(s Step) bool {
	switch s.Kind {
	case StepBridgeAdd, StepBridgeDel:
		return true
	case StepCmd:
		switch s.Argv[0] {
		case "ebtables":
			return true
		case "brctl":
			return len(s.Argv) > 1 && (s.Argv[1] == "addbr" || s.Argv[1] == "delbr" || s.Argv[1] == "addif" || s.Argv[1] == "delif")
		case "ip":
			return len(s.Argv) > 2 && s.Argv[1] == "link" && (s.Argv[2] == "add" || s.Argv[2] == "del")
		}
	}
	return false
}

// withFlush appends one whole-cache flush when steps change the datapath.
func withFlush(steps []Step) []Step {
	for _, s := range steps {
		if datapathStep(s) {
			return append(steps, flushStep())
		}
	}
	return steps
}

// FlushFlows flushes the flow cache for s and then counts the flows left in
// /proc/fcache/brlist for s's MAC or tx interface. Flows still listed are
// logged, not an error: an active stream is re-learnt at once, on its new
// path. Use it after a datapath change made outside this package (decosys,
// the agent's loop guard).
func (a *Applier) FlushFlows(ctx context.Context, s FlowScope) error {
	if s.MAC != "" {
		m := normMAC(s.MAC)
		if m == "" {
			return fmt.Errorf("bcmwifi: flush flows: bad MAC %q", s.MAC)
		}
		s.MAC = m
	}
	if s.If != "" && !ifnameOK(s.If) {
		return fmt.Errorf("bcmwifi: flush flows: bad interface %q", s.If)
	}
	return a.flushFlows(ctx, s)
}

func (a *Applier) flushFlows(ctx context.Context, s FlowScope) error {
	argv := s.argv()
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: %s", strings.Join(argv, " "))
		return nil
	}
	if err := a.run(ctx, argv...); err != nil {
		return fmt.Errorf("bcmwifi: %s: %w", strings.Join(argv, " "), err)
	}
	if n := a.cachedFlows(s); n > 0 {
		a.o.Logf("bcmwifi: %d flows for %s still in the flow cache after the flush (re-learnt on the new path)", n, strings.Join(argv[2:], " "))
	}
	return nil
}

// cachedFlows counts /proc/fcache/brlist rows for s (MAC anywhere in the
// row, or tx_dev equal to s.If); -1 when unreadable or s is whole-cache.
func (a *Applier) cachedFlows(s FlowScope) int {
	if s.MAC == "" && s.If == "" {
		return -1
	}
	b, err := a.readFile("/proc/fcache/brlist")
	if err != nil {
		return -1
	}
	n := 0
	for _, line := range strings.Split(strings.ToLower(string(b)), "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || !strings.HasPrefix(f[0], "0x") {
			continue
		}
		if s.MAC != "" && strings.Contains(line, "<"+s.MAC+">") || s.If != "" && f[len(f)-1] == s.If {
			n++
		}
	}
	return n
}

// ifnameOK accepts a Linux interface name (also used for tc and ebtables
// arguments, which go to argv, never a shell).
func ifnameOK(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// Flow cache on/off while tc shapes (docs/deco/features/client-rate-limit.md).
//
// Measured on .205 (2026-11-19): with the flow cache learning (fc status
// "Flow Learning Enabled", Acceleration Mode L3, HW Acceleration Enabled) a
// station limited to 512/768 kbit/s got 4.9 Mbit/s down and 8.2 up, and the
// htb classes counted ~150 packets: accelerated flows bypass tc entirely,
// and `fc flush --mac` only lets ~14 packets through before the flow is
// learnt again. With `fc disable` the same limits held (473/698 kbit/s) and
// the classes counted the traffic. There is no per-station limit in wl, no
// ebtables skiplog target and no bridge netfilter (so xt_SKIPLOG cannot see
// bridged traffic), and Archer's sysport_tm is per port queue, so the only
// way to make tc limits hold is to stop flow learning on the unit while any
// limit is built. The SSID-wide limits are bypassed the same way.
//
// syncFlowCache is the one place that decides; syncShaping (Apply, Tick,
// SetClientRates, SyncRateLimits) calls it with what it wants shaped:
//
//   - a limit wanted (per-client or SSID-wide, a station associated): the
//     flow cache must be off. When `fc status` says it is learning, `fc
//     disable` then `fc flush`, so flows learnt before take the slow path
//     too. The agent then owns the off state (RunDir/fc-off, and in
//     memory), also when it found the cache already off. Tick runs the sync
//     every minute, so the cache re-enabled by TP-Link or by hand is turned
//     off again.
//   - no limit: `fc enable`, but only when the agent owns the off state. A
//     cache someone else turned off while no limit was set is left alone.
//
// The hand-back to TP-Link enables the cache whoever turned it off (stock
// TP-Link learns flows), and an observe-mode start or a drop to observe
// enables it when an earlier run left it off (RestoreFlowCache). A plain
// stop (SIGTERM, an agent restart or upgrade) leaves the cache as it is,
// like the rest of Wi-Fi: the tc trees stay built and keep limiting only
// while the cache is off, and the next start's first sync decides again.
// A reboot brings the cache back on (it is not saved anywhere).
//
// Nothing is done when `fc status` fails or its first line is not the
// flow-cache line (no fc on the unit; jio-mtk has no bcmwifi at all).

// FlowCacheOffFile, in RunDir, records for this boot that the agent turned
// the flow cache off (the agent looks for it at an observe-mode start).
const FlowCacheOffFile = "fc-off"

func (a *Applier) fcOffPath() string { return path.Join(a.o.RunDir, FlowCacheOffFile) }

// shapeNeed is what wantShaping found to shape: stations limited by their
// own entry, and SSIDs whose limit applies to an associated station.
type shapeNeed struct {
	perClient map[string]bool // station MACs
	ssid      map[string]bool // SSID ids
}

func (n shapeNeed) any() bool { return len(n.perClient)+len(n.ssid) > 0 }

// fcStatus reads whether the flow cache is learning from the first line of
// `fc status` ("Broadcom Packet Flow Cache learning via BLOG enabled." or
// "... disabled."). ok is false when there is no such line (no fc).
func (a *Applier) fcStatus(ctx context.Context) (on, ok bool) {
	out, err := a.o.Run.Run(ctx, "fc", "status")
	line := strings.TrimSpace(firstLine(strings.TrimLeft(string(out), "\r\n\t ")))
	l := strings.ToLower(line)
	if strings.Contains(l, "flow cache") {
		switch {
		case strings.HasSuffix(l, "disabled."), strings.HasSuffix(l, "disabled"):
			a.fcNote = ""
			return false, true
		case strings.HasSuffix(l, "enabled."), strings.HasSuffix(l, "enabled"):
			a.fcNote = ""
			return true, true
		}
	}
	why := fmt.Sprintf("unrecognised first line %q", line)
	if err != nil {
		why = err.Error()
	}
	if why != a.fcNote {
		a.fcNote = why
		a.o.Logf("bcmwifi: flow cache: fc status: %s (no flow cache control: left as it is)", why)
	}
	return false, false
}

// fcOwned reports whether the agent owns the flow cache's off state.
func (a *Applier) fcOwned() bool { return a.fcOff || a.exists(a.fcOffPath()) }

func (a *Applier) setFCOwned(on bool) {
	a.fcOff = on
	if a.o.DryRun {
		return
	}
	if on {
		if err := writeFileAtomic(a.fsPath(a.fcOffPath()), []byte("flow cache turned off by udeco-ap while tc limits are set\n"), 0o644); err != nil {
			a.o.Logf("bcmwifi: flow cache: recording %s: %v", a.fcOffPath(), err)
		}
		return
	}
	if err := os.Remove(a.fsPath(a.fcOffPath())); err != nil && !errors.Is(err, os.ErrNotExist) {
		a.o.Logf("bcmwifi: flow cache: removing %s: %v", a.fcOffPath(), err)
	}
}

// fc runs one fc command (logged; only logged with DryRun).
func (a *Applier) fc(ctx context.Context, args ...string) error {
	argv := append([]string{"fc"}, args...)
	if a.o.DryRun {
		a.o.Logf("bcmwifi dry-run: %s", strings.Join(argv, " "))
		return nil
	}
	if err := a.run(ctx, argv...); err != nil {
		return fmt.Errorf("bcmwifi: %s: %w", strings.Join(argv, " "), err)
	}
	return nil
}

// syncFlowCache turns the flow cache off while need has a limit and back on
// when it has none (see above). Callers hold a.mu.
func (a *Applier) syncFlowCache(ctx context.Context, need shapeNeed) {
	if !need.any() && !a.fcOwned() {
		return // nothing of ours to undo: no fc call at all
	}
	on, ok := a.fcStatus(ctx)
	if !ok {
		return
	}
	if !need.any() {
		if !on {
			if err := a.fc(ctx, "enable"); err != nil {
				a.o.Logf("bcmwifi: flow cache on: %v (retried at the next sync)", err)
				return
			}
			a.o.Logf("bcmwifi: flow cache on: no limits")
		}
		a.setFCOwned(false)
		return
	}
	owned := a.fcOwned()
	if !on {
		if !owned {
			a.setFCOwned(true) // found off: ours to turn on when no limit is left
		}
		return
	}
	if err := a.fc(ctx, "disable"); err != nil {
		a.o.Logf("bcmwifi: flow cache off: %v (limits are bypassed by accelerated flows; retried at the next sync)", err)
		return
	}
	drift := ""
	if owned {
		drift = " (it had been turned back on)"
	} else {
		a.setFCOwned(true)
	}
	a.o.Logf("bcmwifi: flow cache off: %d per-client / %d SSID limits need the slow path%s", len(need.perClient), len(need.ssid), drift)
	// flows learnt before take the slow path too (the per-station
	// flushes that follow cover only the stations whose limit changed)
	if err := a.fc(ctx, "flush"); err != nil {
		a.o.Logf("%v", err)
	}
}

// flowCacheOn enables the flow cache whoever turned it off (hand-back to
// TP-Link). Callers hold a.mu.
func (a *Applier) flowCacheOn(ctx context.Context, why string) {
	on, ok := a.fcStatus(ctx)
	if !ok {
		return
	}
	if !on {
		if err := a.fc(ctx, "enable"); err != nil {
			a.o.Logf("bcmwifi: flow cache on (%s): %v", why, err)
			return
		}
		a.o.Logf("bcmwifi: flow cache on: no limits (%s)", why)
	}
	a.setFCOwned(false)
}

// RestoreFlowCache enables the flow cache when an earlier run of the agent
// (this boot) turned it off for its tc limits and did not turn it back on:
// observe-mode start and the drop to observe, where no limit is built any
// more. It runs nothing when the agent does not own the off state.
func (a *Applier) RestoreFlowCache(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.fcOwned() {
		return nil
	}
	a.syncFlowCache(ctx, shapeNeed{})
	if a.fcOwned() && !a.o.DryRun {
		return fmt.Errorf("bcmwifi: flow cache an earlier run turned off not restored (see the log)")
	}
	return nil
}
