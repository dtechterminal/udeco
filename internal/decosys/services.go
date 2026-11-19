package decosys

import (
	"path"
	"slices"
)

// target is one TP-Link service (or group) in the STOP set of services.md,
// with the verifier's corrections applied.
type target struct {
	// init is the /etc/init.d script, which is also the procd service name.
	init string
	// procs are the program basenames whose presence means the target runs:
	// argv[0], or the script path when argv[0] is a shell (sync-check, radar
	// and the nrd helpers may be shell scripts).
	procs []string
	// match optionally narrows procs (e.g. the two uhttpd instances).
	match func(argv []string) bool
	// procd marks services run by procd: if the init script is missing, the
	// fallback is 'ubus call service delete' rather than a kill, so procd
	// does not respawn the process.
	procd bool
	// kill means there is no usable init script (no stop, or none at all):
	// the daemon is sent SIGTERM by PID. Nothing respawns these except a
	// TP-Link Wi-Fi rebuild, whose callers are stopped first.
	kill bool
	// killRest also SIGTERMs whatever matching processes are still listed
	// after the init stop (dropbear sessions forked by the :20001 listener,
	// which procd does not track).
	killRest bool
	// stopArgs replaces the default "stop" argument.
	stopArgs []string
	// startArgs is what Restore runs; nil means "start". Kill targets are
	// never restarted.
	startArgs []string
	// noRestore keeps Restore from starting the target again (a root shell
	// listener is not worth handing back).
	noRestore bool
	// why is logged with the step.
	why string
}

// Phases follow services.md §4 "Recommended order", with R14 applied:
//  0. local management (tmpsvr, dropbear :20001) first: it is the master's
//     root path into the unit (B9) and nothing on the unit needs it once the
//     agent runs there. Skipped while a firmware upgrade is in flight or the
//     rc.d boot chain still runs (R17, guard.go); the inbound fence blocks
//     :20001 in the meantime,
//  1. things that restart other services (awn, sync, tipc, cloud, IoT),
//  2. the procd config triggers (separate list below),
//  3. the remaining TP-Link daemons,
//  4. script-started daemons and one-shot Wi-Fi rebuild callers (by PID),
//  5. NTP (ntp.go).
var (
	phaseFirst = []target{
		{init: "tmpsvr", procs: []string{"tmpsvr"}, procd: true,
			why: "TMP app API; app-initiated reboot, Wi-Fi changes and firmware sync"},
		{init: "dropbear", procs: []string{"dropbear"}, procd: true, killRest: true,
			match: argv0("/usr/sbin/dropbear"),
			why:   "TP-Link SSH :20001 carrying TMP (/data/dropbear :22 is not touched)"},
	}
	phaseRestarters = []target{
		{init: "awn", procs: []string{"awnd"}, procd: true,
			why: "bounces radios, changes chanspec, runs repacd restart and wifi reload"},
		{init: "sync-server", procs: []string{"sync-server"}, procd: true,
			why: "mesh config sync from the master; runs sync-check and hotplug-call"},
		{init: "tipc-server", procs: []string{"tipc-server"}, procd: true,
			why: "TIPC mesh messaging; remote reboot path"},
		{init: "cloud_brd", procs: []string{"cloud-brd"}, procd: true,
			why: "TP-Link cloud (master only)"},
		// TP-Link's own path: 'mgmt false' runs '/etc/init.d/<p> stop' for each
		// running IoT daemon, iot-wifi-center included (so 'mgmt true' cannot
		// restart the rest). Master only.
		{init: "iot-wifi-center", procs: []string{"iot-wifi-center", "iot-netdev", "iot-tpra", "iot-tapo", "philips-hue", "matter"},
			procd: true, stopArgs: []string{"mgmt", "false"}, startArgs: []string{"mgmt", "true"},
			why: "TP-Link IoT and Hue daemons (master only)"},
		{init: "cloud_client", procs: []string{"cloud-client"}, why: "TP-Link cloud session"},
		{init: "cloud_https", procs: []string{"cloud-https"}, why: "TP-Link cloud"},
		// killRest: seen on .205 (2026-11-19), cloud-proxy running outside
		// procd (respawn is commented out in its init script), so the init
		// stop leaves it running and every enforce pass re-asserted the stop.
		{init: "cloud_proxy", procs: []string{"cloud-proxy"}, procd: true, killRest: true, why: "TP-Link cloud relay"},
		{init: "cloud_pfclient", procs: []string{"cloud-pfclient"}, why: "TP-Link cloud proxy client"},
		{init: "msgcenter", procs: []string{"msgcenterd"}, procd: true, why: "app notifications"},
	}
	phaseDaemons = []target{
		// Shell loops that wait and then run '/etc/init.d/nrd restart'
		// (services.md §2). Killed before nrd stops so they cannot bring it
		// back. Not init scripts: only nrd's start_service spawns them.
		{init: "start_nrd", procs: []string{"start_nrd", "bcm_nrd_check_acs"}, kill: true,
			why: "loops until it can run nrd restart"},
		{init: "nrd", procs: []string{"nrd"}, procd: true, why: "band steering: deauths and driver MAC deny lists"},
		{init: "wpsd", procs: []string{"wpsd"}, procd: true, why: "WPS; reloads on wifi config"},
		{init: "conn-indicator", procs: []string{"conn-indicator"}, procd: true, why: "probes the internet, drives the LED"},
		{init: "server-probe", procs: []string{"server-probe"}, procd: true, why: "WAN probe"},
		{init: "wan", procs: []string{"wanDetection"}, why: "WAN port detection; restarts imsnoop/iptv"},
		{init: "client_mgmt", procs: []string{"client_mgmt", "client_upload"}, procd: true, why: "client list upload to the app"},
		{init: "dhcp_hook_d", procs: []string{"dhcp_hook_d"}, why: "client hostname sniffing"},
		{init: "msg_server", procs: []string{"msg_server"}, procd: true, why: "app notifications"},
		{init: "tfstats", procs: []string{"tfstats"}, procd: true, why: "per-client traffic statistics"},
		{init: "tsched", procs: []string{"tsched"}, procd: true, why: "scheduler: LED night mode, reboot schedule, flash writes"},
		{init: "uhttpd", procs: []string{"uhttpd"}, procd: true, match: not(hasArg("/var/firmwares")),
			why: "local web UI; its Lua handlers run repacd restart and /sbin/wifi"},
		{init: "uhttpd-fw", procs: []string{"uhttpd"}, procd: true, match: hasArg("/var/firmwares"),
			why: "firmware distribution"},
		// R18/Q14: rsched is a procd instance of reboot_schedule; it is not
		// running on the captured units, so this only acts when it is.
		{init: "reboot_schedule", procs: []string{"rsched"}, procd: true, why: "scheduled reboots"},
	}
	phaseKills = []target{
		// Keep /tmp/acsd2_channel_select_done: without it bcm_service would
		// start acsd2 again.
		{init: "acsd2", procs: []string{"acsd2"}, kill: true, why: "moves channels at runtime"},
		// handheld_radar's init has no stop; radar runs 'repacd restart'.
		{init: "handheld_radar", procs: []string{"handheld_radar", "radar"}, kill: true,
			why: "runs repacd restart"},
		// One-shot, run by sync-server; runs 'repacd start fix_default_config'.
		{init: "sync-check", procs: []string{"sync-check"}, kill: true, why: "runs repacd start"},
		// R18. Debug and factory listeners: never part of a running AP.
		{init: "tddp", procs: []string{"tddp"}, kill: true, why: "TP-Link debug protocol listener"},
		// The telnet init script is procd (no respawn); stopped through it,
		// and never restarted by Restore.
		{init: "telnet", procs: []string{"telnetd"}, procd: true, noRestore: true, why: "telnet root shell"},
		// time_settings starts it on a satellite; it polls the master every
		// ~64 s forever once the master is not TP-Link (audit X5).
		{init: "update_dst_from_ap", procs: []string{"update_dst_from_ap"}, kill: true,
			why: "polls the master for the time zone forever"},
		// The subshell '/etc/init.d/cloud_client start' leaves waiting for
		// the NTP marker the agent's ntpd never writes (audit X1, X4).
		{init: "cloud_client-wait", procs: []string{"rc.common"}, kill: true,
			match: func(argv []string) bool {
				return len(argv) >= 3 && argv[1] == "/etc/init.d/cloud_client" && argv[2] == "start"
			},
			why: "cloud_client start waiting for NTP forever"},
	}
)

// triggerServices are procd services with no instance whose only job is a
// config.change trigger (services.md §2, verifier "Confirmed"):
//   - wifi: 'reload' runs '/etc/init.d/repacd restart' (full Wi-Fi rebuild),
//   - sysmode: 'reload' runs 'reboot -f' when the mode changes,
//   - guest_eth, guest-schedule, guest-bandwidth: reload on package 'wifi',
//   - leds_night_mode: a 'leds' config change runs 'ubus call leds switch on',
//     which would undo a UniFi "LED off" (audit X3, R18),
//   - time_settings: reload restarts update_dst_from_ap (audit X5, R18).
//
// They are dropped with 'ubus call service delete {"name":X}', which is
// exactly what rc.common's stop() does after the script's stop_service. The
// stop_service step is skipped on purpose: wifi, sysmode, guest_eth and
// guest-schedule define none, and guest-bandwidth's writes
// /proc/traffic_control/guest, which is not ours to change. Running
// '/etc/init.d/X stop' would also source TP-Link's function libraries for no
// benefit. imsnoop (KEEP) also reloads on 'wifi'; that only reloads imsnoop
// and is left alone. wpsd's trigger goes away with wpsd.
var triggerServices = []string{"wifi", "sysmode", "guest_eth", "guest-schedule", "guest-bandwidth",
	"leds_night_mode", "time_settings"}

// allTargets lists every stop target in execution order.
func allTargets() []target {
	return slices.Concat(phaseFirst, phaseRestarters, phaseDaemons, phaseKills)
}

// matches reports whether a process belongs to the target. A script run by
// a shell matches by the script's name (program).
func (t target) matches(argv []string) bool {
	argv = program(argv)
	if len(argv) == 0 || !slices.Contains(t.procs, path.Base(argv[0])) {
		return false
	}
	return t.match == nil || t.match(argv)
}

func hasArg(a string) func([]string) bool {
	return func(argv []string) bool { return slices.Contains(argv[1:], a) }
}

func not(f func([]string) bool) func([]string) bool {
	return func(argv []string) bool { return !f(argv) }
}

func argv0(p string) func([]string) bool {
	return func(argv []string) bool { return argv[0] == p }
}
