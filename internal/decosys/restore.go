package decosys

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Restore is the best-effort undo for rollback or uninstall. It removes the
// egress firewall and the inbound fence (TP-Link's mesh needs :20001 and
// :20002 back; call Ingress(true) afterwards to keep the fence in observe
// mode), stops the agent's ntpd and restarts TP-Link's, puts the TP-Link
// cron jobs back (the persist_shell.sh line stays), restarts, in reverse stop
// order, the services that Enforce recorded as stopped (the record lives in
// /etc/udeco, a ramfs, so it survives an agent restart but not a reboot),
// replays TP-Link's br-lan QoS and puts TP-Link's reset-button script back.
//
// Some things are deliberately not undone, and only a reboot restores them:
//   - the procd trigger services (wifi, sysmode, guest-*): re-registering them
//     means running their start_service, which for wifi re-runs calibration
//     checks and writes kernel nvram;
//   - daemons that were killed by PID (acsd2, radar, sync-check, tddp,
//     update_dst_from_ap): they are started only by a TP-Link Wi-Fi rebuild
//     or by boot, and telnet is never started again;
//   - deleted br-lan addresses and killed DHCP servers: both are harmful.
//
// Ethernet ports the agent's loop guard took out of br-lan (LoopGuardFile)
// are put back (brctl addif, then a flow flush, R21): TP-Link's br-lan has
// both ports, and a port left out could be the only cable later.
//
// Restarting awn hands the unit back to TP-Link's mesh logic, which may run
// its own Wi-Fi rebuild (repacd); that is stock behaviour, not something
// Restore runs. For a guaranteed stock state, reboot.
func (m *Manager) Restore(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	errs := []error{m.egress(ctx, false), m.ingress(ctx, false), m.restoreLoopGuard(ctx)}

	procs, err := m.readProcs()
	if err != nil {
		return errors.Join(append(errs, err)...)
	}
	stopped, err := m.readLines(stoppedFile)
	errs = append(errs, err)

	// NTP: the agent's ntpd goes, TP-Link's comes back.
	var ours []int
	for _, p := range procs {
		if m.o.GatewayIP != "" && m.isOurNTP(p.argv) {
			ours = append(ours, p.pid)
		}
	}
	if len(ours) > 0 {
		s := m.killStep("udeco-ntpd", "restore", ours, m.isOurNTP)
		if m.o.DryRun {
			m.o.Logf("decosys: dry-run: %s", s)
		} else {
			errs = append(errs, m.exec(ctx, s), m.remove(ntpdPidfile))
		}
	}
	if slices.Contains(stopped, sysntpdInit) && m.exists("/etc/init.d/"+sysntpdInit) {
		errs = append(errs, m.mutate(ctx, "/etc/init.d/"+sysntpdInit, "start"))
	}

	errs = append(errs, m.restoreCron())

	ts := allTargets()
	slices.Reverse(ts)
	for _, t := range ts {
		init := "/etc/init.d/" + t.init
		if t.kill || t.noRestore || !slices.Contains(stopped, t.init) || !m.exists(init) || len(matching(t, procs)) > 0 {
			continue
		}
		args := t.startArgs
		if args == nil {
			args = []string{"start"}
		}
		errs = append(errs, m.mutate(ctx, init, args...))
	}

	errs = append(errs, m.restoreQdisc(ctx), m.restoreButton())

	if !m.o.DryRun {
		errs = append(errs, m.remove(stoppedFile))
		m.triggersClean = false
		m.tookOver = false
	}
	return errors.Join(errs...)
}

// RestoreLoopGuard is the loop-guard part of Restore alone: the ports listed
// in LoopGuardFile go back into LANDev (brctl addif, flow flush) and the
// record is removed once every port is back. An agent that starts in observe
// mode while an earlier takeover run's record is still on ramfs uses it:
// nothing else of the unit is touched.
func (m *Manager) RestoreLoopGuard(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.restoreLoopGuard(ctx)
}

// restoreLoopGuard puts the ports listed in LoopGuardFile back into LANDev
// (a port already a bridge member is left alone) and removes the record.
//
// A port is put back only when that cannot close the loop it was taken out
// for: it has no carrier, or no other Ethernet port of LANDev has carrier.
// br-lan runs without STP and forwards at once (interference-audit B7), so
// re-adding a port whose cable still loops back to the LAN would start a
// broadcast storm for the whole network. Such a port stays out (logged, and
// kept in the record, which the next reboot clears with br-lan rebuilt).
func (m *Manager) restoreLoopGuard(ctx context.Context) error {
	if m.o.LoopGuardFile == "" {
		return nil
	}
	ports, err := m.readLines(m.o.LoopGuardFile)
	if err != nil {
		return err
	}
	var errs []error
	var kept []string
	for _, l := range ports {
		f := strings.Fields(l)
		if len(f) == 0 || !strings.HasPrefix(f[0], "eth") || strings.ContainsAny(f[0], "/.") {
			continue
		}
		p := f[0]
		if m.exists("/sys/class/net/" + p + "/brport") {
			continue
		}
		if other := m.cabledLANPort(p); m.carrier(p) && other != "" {
			m.o.Logf("decosys: ALERT: loop guard: %s stays out of %s: it and %s both have carrier, and %s was taken out for a loop (br-lan has no STP); unplug one cable or reboot", p, m.o.LANDev, other, p)
			kept = append(kept, l)
			continue
		}
		m.o.Logf("decosys: loop guard: %s back into %s (restore)", p, m.o.LANDev)
		if err := m.mutate(ctx, m.bin("brctl"), "addif", m.o.LANDev, p); err != nil {
			errs = append(errs, err)
			continue
		}
		if err := m.flushFlows(ctx, FlowScope{Dev: p}); err != nil {
			errs = append(errs, err)
		}
	}
	if !m.o.DryRun && len(errs) == 0 {
		if len(kept) > 0 {
			return m.writeFile(m.o.LoopGuardFile, kept, 0o600)
		}
		return m.remove(m.o.LoopGuardFile)
	}
	return errors.Join(errs...)
}

// carrier reports whether a network device has link (sysfs carrier 1).
func (m *Manager) carrier(dev string) bool {
	b, err := os.ReadFile(filepath.Join(m.o.Root, "/sys/class/net", dev, "carrier"))
	return err == nil && strings.TrimSpace(string(b)) == "1"
}

// cabledLANPort returns an Ethernet port of LANDev other than except that
// has carrier ("" none).
func (m *Manager) cabledLANPort(except string) string {
	ents, err := os.ReadDir(filepath.Join(m.o.Root, "/sys/class/net", m.o.LANDev, "brif"))
	if err != nil {
		return ""
	}
	for _, e := range ents {
		if n := e.Name(); n != except && strings.HasPrefix(n, "eth") && m.carrier(n) {
			return n
		}
	}
	return ""
}
