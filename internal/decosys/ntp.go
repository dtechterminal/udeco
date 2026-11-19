package decosys

import (
	"context"
	"errors"
	"os"
	"path"
	"path/filepath"
	"slices"
)

const (
	// sysntpdInit is TP-Link's procd NTP service. It runs
	// '/usr/sbin/ntpd -n -C -p <pool names>'. The hotplug script
	// iface/98-sysntpd restarts it only on a wan ifup, which never fires in
	// AP mode (audit R30); Enforce still checks for it every pass, since
	// the boot chain starts it late (about 82 s).
	sysntpdInit = "sysntpd"
	// ntpdPidfile is written by start-stop-daemon for the agent's ntpd.
	ntpdPidfile = "/var/run/udeco-ntpd.pid"
)

// ntpArgs is the agent's ntpd command line after argv[0]: busybox ntpd in
// the foreground, client only, asking only the gateway.
func (m *Manager) ntpArgs() []string { return []string{"-n", "-p", m.o.GatewayIP} }

// isNTPD reports whether argv is any ntpd.
func isNTPD(argv []string) bool { return path.Base(argv[0]) == "ntpd" }

// isOurNTP reports whether argv is the agent's ntpd.
func (m *Manager) isOurNTP(argv []string) bool {
	return isNTPD(argv) && slices.Equal(argv[1:], m.ntpArgs())
}

// ntpSteps replaces TP-Link's pool-based ntpd with the agent's. With no
// GatewayIP it leaves ntpd alone.
//
// The agent's ntpd is started detached by busybox start-stop-daemon (-b:
// fork, setsid, stdio to /dev/null) because Runner waits for the command to
// exit. A pidfile is the match criterion: busybox's -x compares the
// executable's inode, and every busybox applet (crond, udhcpc, ash) would
// match it. The stale pidfile is removed first; /proc already showed that the
// agent's ntpd is not running. Enforce is the supervisor: it starts ntpd
// again on the next pass if it has died.
func (m *Manager) ntpSteps(procs []proc) []Step {
	if m.o.GatewayIP == "" {
		return nil
	}
	var ours, tplink, other []int
	for _, p := range procs {
		switch {
		case !isNTPD(p.argv):
		case m.isOurNTP(p.argv):
			ours = append(ours, p.pid)
		case slices.Contains(p.argv, "-C"): // sysntpd's start_service adds -C
			tplink = append(tplink, p.pid)
		default:
			other = append(other, p.pid)
		}
	}

	var steps []Step
	if len(tplink) > 0 {
		if init := "/etc/init.d/" + sysntpdInit; m.exists(init) {
			steps = append(steps, Step{Kind: KindNTP, Target: sysntpdInit,
				Reason: "TP-Link ntpd queries public pools", Cmd: []string{init, "stop"}})
		} else {
			other = append(other, tplink...)
		}
	}
	if len(ours) > 1 {
		other = append(other, ours[1:]...)
	}
	if len(other) > 0 {
		s := m.killStep("ntpd", "ntpd not asking the gateway", other, isNTPD)
		s.Kind = KindNTP
		steps = append(steps, s)
	}
	if len(ours) == 0 {
		ntpd := m.bin("ntpd")
		cmd := append([]string{m.bin("start-stop-daemon"), "-S", "-b", "-m", "-p", ntpdPidfile, "-x", ntpd, "--"}, m.ntpArgs()...)
		steps = append(steps, Step{Kind: KindNTP, Target: "udeco-ntpd",
			Reason: "NTP from the gateway only", Cmd: cmd,
			do: func(ctx context.Context) error {
				if err := os.Remove(filepath.Join(m.o.Root, ntpdPidfile)); err != nil && !errors.Is(err, os.ErrNotExist) {
					return err
				}
				_, err := m.o.Run.Run(ctx, cmd[0], cmd[1:]...)
				return err
			}})
	}
	return steps
}
