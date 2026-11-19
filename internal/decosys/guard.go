package decosys

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// Guard lists what is in flight on the unit that the agent must not
// interfere with (R17). The agent's boot gate (R1) waits while Upgrade or
// Boot is non-empty, and it applies no Wi-Fi change while any field is.
type Guard struct {
	// Rebuild: a TP-Link Wi-Fi rebuild (repacd, /sbin/wifi). Reported,
	// never interrupted: stopping repacd half way can leave the radios down.
	Rebuild []string
	// Upgrade: a firmware upgrade in flight (upgrade processes or marker
	// files). While it is, Enforce does not stop tmpsvr or dropbear :20001,
	// the fence is not installed, and no upgrade process is ever signalled.
	Upgrade []string
	// Boot: rc.d boot scripts still running (/etc/rc.common /etc/rc.d/S*).
	// tmpsvr and dropbear are not stopped while their start may still run.
	Boot []string
}

// Hold reports whether anything is in flight.
func (g Guard) Hold() bool { return len(g.Rebuild)+len(g.Upgrade)+len(g.Boot) > 0 }

// Warning prefixes in Report.Warnings. The rebuild one is matched by the
// agent (cmd/udeco-ap wifi.go rebuildWarning) and must not change.
const (
	WarnRebuild = "TP-Link Wi-Fi rebuild in progress"
	WarnUpgrade = "TP-Link firmware upgrade in progress"
	WarnBoot    = "TP-Link boot scripts still running"
)

// upgradeFiles are markers the flash path leaves while it runs (ctl_sync
// strings, audit B10). /var is a symlink to /tmp on the unit.
var upgradeFiles = []string{"/tmp/firmware_upgrade_flag", "/var/run/force_upgrade.pid"}

// upgradeDir exists (empty) on a normal unit; a file in it means an image is
// being staged.
const upgradeDir = "/tmp/upgrade"

// upgrading reports whether a process belongs to the firmware flash path:
// /usr/bin/upgrade (a script), 'nvrammanager -u' (the flash write itself)
// or sshhttpget (the image download from the master).
func upgrading(argv []string) bool {
	if slices.Contains(argv, "/usr/bin/upgrade") {
		return true
	}
	switch path.Base(program(argv)[0]) {
	case "nvrammanager":
		return slices.ContainsFunc(argv[1:], func(a string) bool { return strings.HasPrefix(a, "-u") })
	case "sshhttpget":
		return true
	}
	return false
}

// protected reports whether a process must never be signalled, whatever
// target matched it: anything on the flash path, and nvrammanager in any
// mode (it writes flash partitions).
func protected(argv []string) bool {
	return upgrading(argv) || path.Base(program(argv)[0]) == "nvrammanager"
}

// booting reports whether a process is an rc.d boot script (procd runs
// '/etc/rc.d/S* boot' through rc.common).
func booting(argv []string) bool {
	return slices.ContainsFunc(argv, func(a string) bool { return strings.HasPrefix(a, "/etc/rc.d/S") })
}

// guard inspects procs and the marker files.
func (m *Manager) guard(procs []proc) Guard {
	var g Guard
	desc := func(pr proc) string { return fmt.Sprintf("pid %d: %s", pr.pid, strings.Join(pr.argv, " ")) }
	for _, pr := range procs {
		switch {
		case upgrading(pr.argv):
			g.Upgrade = append(g.Upgrade, desc(pr))
		case rebuilding(pr.argv):
			g.Rebuild = append(g.Rebuild, desc(pr))
		case booting(pr.argv):
			g.Boot = append(g.Boot, desc(pr))
		}
	}
	for _, f := range upgradeFiles {
		if m.exists(f) {
			g.Upgrade = append(g.Upgrade, f)
		}
	}
	if ents, err := os.ReadDir(filepath.Join(m.o.Root, upgradeDir)); err == nil && len(ents) > 0 {
		g.Upgrade = append(g.Upgrade, fmt.Sprintf("%s/%s (%d file(s))", upgradeDir, ents[0].Name(), len(ents)))
	}
	return g
}

// warnings renders g for Report.Warnings.
func (g Guard) warnings() []string {
	var w []string
	for _, s := range g.Upgrade {
		w = append(w, fmt.Sprintf("%s (%s): tmpsvr and dropbear :20001 left running, no UDECO-IN change", WarnUpgrade, s))
	}
	for _, s := range g.Rebuild {
		w = append(w, fmt.Sprintf("%s (%s); not interrupted", WarnRebuild, s))
	}
	for _, s := range g.Boot {
		w = append(w, fmt.Sprintf("%s (%s): tmpsvr and dropbear :20001 not stopped yet", WarnBoot, s))
	}
	return w
}

// Guard reports what is in flight now, without changing anything. The
// agent's boot gate (R1) uses it.
func (m *Manager) Guard(ctx context.Context) (Guard, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	procs, err := m.readProcs()
	if err != nil {
		return Guard{}, fmt.Errorf("read /proc: %w", err)
	}
	return m.guard(procs), nil
}
