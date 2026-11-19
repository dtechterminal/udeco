package decosys

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The reset button (audit B4, R11). procd's hotplug.json runs
// /etc/rc.button/reset for every button event (pressed and released, with
// BUTTON and SEEN in the environment). TP-Link's script factory-resets on
// ACTION=pressed, with no hold time: one brush of the button wipes the
// takeover and the firewall include, so the unit comes back stock without
// root until it is re-rooted.
//
// The wrapper replaces it at runtime only. /etc is a ramfs, so a reboot
// (power cycle) always brings back TP-Link's script, and Restore puts it
// back without one. It ignores the press, and on release execs TP-Link's
// script with ACTION=pressed only after a hold of 5 s or more. If the kernel
// sends no SEEN on release (audit Q18 is open), the button does nothing
// until the next reboot; a power cycle is the recovery either way, since
// every takeover change is lost on reboot.
const (
	// resetMarker identifies any udeco-ap wrapper (cmd/udeco-ap's guard.go
	// uses the same tag), so a wrapper is never saved as TP-Link's script.
	resetMarker = "udeco-ap reset wrapper"
	resetButton = "/etc/rc.button/reset"
	resetBackup = stateDir + "/reset.tplink"
	resetHold   = 5 // seconds
)

// resetWrapper returns the wrapper script, with TP-Link's script saved at
// orig. It never runs anything but logger and, after a long hold, orig.
func resetWrapper(orig string) string {
	return fmt.Sprintf(`#!/bin/sh
# %[3]s (decosys; runtime only: /etc is a ramfs, a reboot restores TP-Link's script).
# TP-Link's script (saved as %[1]s) factory-resets on the press itself.
# This one waits for the release and resets only after a hold of %[2]d s or more.
case "$ACTION" in
released)
	if [ "${SEEN:-0}" -ge %[2]d ] 2>/dev/null; then
		logger -t udeco-ap "reset button held ${SEEN}s: factory reset"
		ACTION=pressed
		export ACTION
		exec /bin/sh %[1]s "$@"
	fi
	logger -t udeco-ap "reset button released after ${SEEN:-?}s: ignored (hold %[2]d s to factory-reset)"
	;;
*)
	logger -t udeco-ap "reset button $ACTION: ignored until release"
	;;
esac
exit 0
`, orig, resetHold, resetMarker)
}

// buttonStep returns the step that installs the wrapper, or nil when it is
// in place or there is no reset handler to wrap.
func (m *Manager) buttonStep() *Step {
	cur, err := os.ReadFile(filepath.Join(m.o.Root, resetButton))
	if err != nil {
		return nil
	}
	w := resetWrapper(resetBackup)
	if string(cur) == w {
		return nil
	}
	return &Step{Kind: KindButton, Target: resetButton,
		Reason: fmt.Sprintf("factory reset only after a %d s hold (TP-Link's resets on a press)", resetHold),
		do: func(context.Context) error {
			// Save whatever is there now unless it is a wrapper (an older
			// agent's): it is TP-Link's, on the first install or because
			// something put the stock file back since.
			cur, err := os.ReadFile(filepath.Join(m.o.Root, resetButton))
			if err != nil {
				return err
			}
			if !strings.Contains(string(cur), resetMarker) {
				if err := m.writeRaw(resetBackup, cur, 0o755); err != nil {
					return err
				}
			}
			return m.writeRaw(resetButton, []byte(w), 0o755)
		}}
}

// restoreButton puts TP-Link's reset script back.
func (m *Manager) restoreButton() error {
	b, err := os.ReadFile(filepath.Join(m.o.Root, resetBackup))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if m.o.DryRun {
		m.o.Logf("decosys: dry-run: restore %s", resetButton)
		return nil
	}
	if err := m.writeRaw(resetButton, b, 0o755); err != nil {
		return err
	}
	m.o.Logf("decosys: restored TP-Link's %s", resetButton)
	return m.remove(resetBackup)
}
