package decosys

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// Watch kinds: report-only findings (Finding.Kind) that are not steps.
const (
	WatchSmartIP  = "smartip"     // smartipd logged a disconnect, clear ip, phy-power or udhcpc restart
	WatchProcess  = "process"     // a 'wifi disconn*' or 'ethctl ... phy-power' process is running
	WatchDHCPD    = "dhcpd-other" // a DHCP server on a bridge other than br-lan (not killed)
	WatchHook     = "hook"        // the firewall include for /data/persist_shell.sh is missing
	WatchCrond    = "crond"       // crond is not running (no cron supervision)
	WatchApsd     = "apsd"        // apsd is not running (R19: reported, not restarted)
	WatchImsnoop  = "imsnoop"     // imsnoop restarted or is not running
	WatchWorkMode = "work_mode"   // /tmp/work_mode changed since the first Enforce
	WatchUnitIP   = "unit-ip"     // UnitIP is not on br-lan
	WatchQdisc    = "qdisc-other" // a root qdisc on br-lan that is not TP-Link's htb 2:
	WatchError    = "watch-error" // a watch could not read its input (ip, tc)
)

const (
	firewallConfig = "/etc/config/firewall"
	persistScript  = "/data/persist_shell.sh"
	workModeFile   = "/tmp/work_mode"
	// logLines is how much of logd's ring each pass reads (logread -l).
	logLines = "200"
)

// lanAddrs returns the IPv4 addresses (CIDR) on the LAN bridge, or ok=false
// when ip is not available.
func (m *Manager) lanAddrs(ctx context.Context) (addrs []string, ok bool, err error) {
	ip := m.bin("ip")
	if !strings.HasPrefix(ip, "/") {
		m.note("no-ip", "ip not found: the br-lan address watch (R8a) is off")
		return nil, false, nil
	}
	out, err := m.o.Run.Run(ctx, ip, "-o", "-4", "addr", "show", "dev", m.o.LANDev)
	if err != nil {
		return nil, false, fmt.Errorf("ip addr show %s: %w", m.o.LANDev, err)
	}
	for _, l := range strings.Split(string(out), "\n") {
		f := strings.Fields(l)
		for i := 0; i+1 < len(f); i++ {
			if f[i] == "inet" {
				if _, _, err := net.ParseCIDR(f[i+1]); err == nil {
					addrs = append(addrs, f[i+1])
				}
				break
			}
		}
	}
	return addrs, true, nil
}

// addrIP returns the address part of a CIDR.
func addrIP(cidr string) string {
	ip, _, _ := strings.Cut(cidr, "/")
	return ip
}

// addrSteps deletes IPv4 addresses on br-lan that are not the unit's lease
// (R8a). TP-Link's netifd holds the lan config 192.168.0.1/22, the
// gateway's own address, and re-adds it on a netifd respawn or ifup (B5):
// br-lan would then answer ARP for the gateway.
//
// Lock-out safety:
//   - UnitIP counts as the lease only when it is neither the gateway's nor
//     the controller's address (a reading taken while TP-Link's default was
//     back would otherwise make the alias "the lease" and delete the real
//     one);
//   - an address equal to the gateway's or the controller's is always
//     deleted (that one is always wrong);
//   - any other address is deleted only while the lease is on br-lan, and
//     never when it lies inside LANCIDR (or LANCIDR is unknown): that can
//     be a new lease the agent has not been told about yet (a DHCP change
//     racing SetLAN), and deleting it would cut the unit off;
//   - after a delete the lease is checked and re-added if the kernel dropped
//     it with the deleted address.
func (m *Manager) addrSteps(ctx context.Context) ([]Step, []Finding, error) {
	addrs, ok, err := m.lanAddrs(ctx)
	if !ok || err != nil {
		return nil, nil, err
	}
	lease := m.o.UnitIP
	if lease == m.o.GatewayIP || lease == m.o.ControllerIP {
		lease = ""
	}
	var unit string
	for _, a := range addrs {
		if lease != "" && addrIP(a) == lease {
			unit = a
		}
	}
	var lan *net.IPNet
	if m.o.LANCIDR != "" {
		_, lan, _ = net.ParseCIDR(m.o.LANCIDR)
	}
	notes := m.edge(WatchUnitIP, "unit-ip", m.o.UnitIP != "" && unit == "",
		fmt.Sprintf("the unit's lease %s is not on %s (have %v): only the gateway's address is removed", m.o.UnitIP, m.o.LANDev, addrs))
	var steps []Step
	for _, a := range addrs {
		ip := addrIP(a)
		bad := ip != "" && (ip == m.o.GatewayIP || ip == m.o.ControllerIP)
		inLAN := lan == nil || lan.Contains(net.ParseIP(ip))
		if a == unit || !bad && (unit == "" || inLAN) {
			continue
		}
		why := "not the unit's lease " + lease + " and outside " + m.o.LANCIDR
		if bad {
			why = "the gateway's/controller's own address: br-lan would answer ARP for it"
		}
		cmd := []string{m.bin("ip"), "addr", "del", a, "dev", m.o.LANDev}
		steps = append(steps, Step{Kind: KindAddr, Target: m.o.LANDev + " " + a, Reason: why, Cmd: cmd,
			do: func(ctx context.Context) error {
				m.o.Logf("decosys: ALERT: foreign address %s on %s (%s): deleting", a, m.o.LANDev, why)
				_, err := m.o.Run.Run(ctx, cmd[0], cmd[1:]...)
				if unit == "" {
					return err
				}
				// Deleting a primary can take its secondaries with it.
				now, _, rerr := m.lanAddrs(ctx)
				if rerr == nil && !slices.Contains(now, unit) {
					m.o.Logf("decosys: ALERT: lease %s left %s with %s: re-adding", unit, m.o.LANDev, a)
					_, aerr := m.o.Run.Run(ctx, cmd[0], "addr", "add", unit, "brd", "+", "dev", m.o.LANDev)
					err = errors.Join(err, aerr)
				}
				return errors.Join(err, rerr)
			}})
	}
	return steps, notes, nil
}

// dhcpServers are DHCP server programs. The unit is an AP: nothing on it
// serves DHCP. smartipd starts udhcpd on br-lan when the master's DHCP
// detection fails (B6), with the gateway's own address as router.
var dhcpServers = []string{"udhcpd", "dhcpd"}

// dhcpdIface returns the interface a DHCP server serves, "" when unknown.
func (m *Manager) dhcpdIface(argv []string) string {
	if path.Base(argv[0]) == "dhcpd" { // ISC: interfaces are the trailing arguments
		for _, a := range argv[1:] {
			if a == m.o.LANDev {
				return a
			}
		}
		return ""
	}
	// busybox: udhcpd [-fS] [-I ADDR] [-a MSEC] [-P PORT] [CONFFILE]
	conf := "/etc/udhcpd.conf"
	for i := 1; i < len(argv); i++ {
		switch a := argv[i]; {
		case a == "-I" || a == "-a" || a == "-P":
			i++
		case !strings.HasPrefix(a, "-"):
			conf = a
		}
	}
	b, err := os.ReadFile(filepath.Join(m.o.Root, conf))
	if err != nil {
		return ""
	}
	for _, l := range strings.Split(string(b), "\n") {
		if f := strings.Fields(l); len(f) >= 2 && f[0] == "interface" {
			return f[1]
		}
	}
	return ""
}

// dhcpdSteps kills DHCP servers on br-lan (or on an interface it cannot
// tell, which on an AP is br-lan) and reports the others.
func (m *Manager) dhcpdSteps(procs []proc) ([]Step, []Finding) {
	var steps []Step
	var notes []Finding
	for _, pr := range procs {
		if !slices.Contains(dhcpServers, path.Base(pr.argv[0])) {
			continue
		}
		ifc := m.dhcpdIface(pr.argv)
		if ifc != "" && ifc != m.o.LANDev {
			if m.cond(fmt.Sprintf("pid:%d:dhcpd", pr.pid), "on") {
				notes = append(notes, Finding{Kind: WatchDHCPD, Detail: fmt.Sprintf("pid %d serves %s: %s", pr.pid, ifc, strings.Join(pr.argv, " "))})
			}
			continue
		}
		argv0 := pr.argv[0]
		s := m.killStep(path.Base(argv0), "DHCP server on "+m.o.LANDev+" (a rogue server for the whole LAN)",
			[]int{pr.pid}, func(a []string) bool { return a[0] == argv0 })
		s.Kind = KindDHCPD
		steps = append(steps, s)
	}
	return steps, notes
}

// cond records the state of a watch condition and reports whether it
// changed since the last pass (edge triggering, so a lasting condition is
// reported once, and again when it clears).
func (m *Manager) cond(key, state string) bool {
	if m.conds[key] == state {
		return false
	}
	if state == "" {
		delete(m.conds, key)
	} else {
		m.conds[key] = state
	}
	return true
}

// edge returns a finding when the condition key changes: detail when it
// appears, "cleared" when it goes away.
func (m *Manager) edge(kind, key string, on bool, detail string) []Finding {
	state := ""
	if on {
		state = detail
	}
	if !m.cond(key, state) {
		return nil
	}
	if !on {
		detail = "cleared"
	}
	return []Finding{{Kind: kind, Detail: detail}}
}

// smartipAlarm matches the smartipd log lines that mean it acted on the
// LAN or the radios (audit B6, R8b).
var smartipAlarm = regexp.MustCompile(`(?i)disconnect|clear ip|phy-power|restart udhcpc`)

// watch runs the report-only checks (R8b, R10, R19). Callers hold m.mu.
func (m *Manager) watch(ctx context.Context, procs []proc) []Finding {
	var res []Finding
	running := func(base string) []int {
		var pids []int
		for _, pr := range procs {
			if path.Base(program(pr.argv)[0]) == base {
				pids = append(pids, pr.pid)
			}
		}
		return pids
	}

	// smartipd's children that act on clients or the uplink (B6). Never
	// killed: cutting 'ethctl phy-power down/up' half way leaves the PHY down.
	for _, pr := range procs {
		argv := program(pr.argv)
		b := path.Base(argv[0])
		if b == "wifi" && slices.ContainsFunc(argv[1:], func(a string) bool { return strings.HasPrefix(a, "disconn") }) ||
			b == "ethctl" && slices.Contains(argv[1:], "phy-power") {
			res = append(res, m.edge(WatchProcess, fmt.Sprintf("proc-%d", pr.pid), true,
				fmt.Sprintf("pid %d: %s", pr.pid, strings.Join(pr.argv, " ")))...)
		}
	}
	// Per-process conditions end with their process.
	for k := range m.conds {
		if rest, ok := strings.CutPrefix(k, "pid:"); ok {
			pid, _, _ := strings.Cut(rest, ":")
			if !slices.ContainsFunc(procs, func(p proc) bool { return fmt.Sprint(p.pid) == pid }) {
				delete(m.conds, k)
			}
		}
	}

	res = append(res, m.smartipLog(ctx)...)

	// The boot hook (B11, R10h): without the firewall include nothing
	// starts /data/dropbear or the agent after a reboot.
	b, err := os.ReadFile(filepath.Join(m.o.Root, firewallConfig))
	hook := err == nil && hasInclude(b, persistScript)
	res = append(res, m.edge(WatchHook, "hook", !hook,
		"no firewall include runs "+persistScript+": the next reboot comes up without root SSH or the agent")...)
	res = append(res, m.edge(WatchCrond, "crond", len(running("crond")) == 0,
		"crond is not running: nothing restarts the agent or /data/dropbear")...)
	res = append(res, m.edge(WatchApsd, "apsd", len(running("apsd")) == 0,
		"apsd is not running (not restarted: TP-Link's bridge port typing is unmanaged)")...)

	ims := running("imsnoop")
	res = append(res, m.edge(WatchImsnoop, "imsnoop", len(ims) == 0, "imsnoop is not running")...)
	if len(ims) > 0 {
		if m.imsnoopPID != 0 && ims[0] != m.imsnoopPID {
			res = append(res, Finding{Kind: WatchImsnoop, Detail: fmt.Sprintf("imsnoop restarted (pid %d -> %d): br-lan multicast tables rebuilt", m.imsnoopPID, ims[0])})
		}
		m.imsnoopPID = ims[0]
	}

	// The role smartipd and apsd act on (R10b). Frozen once awnd is stopped.
	wm, err := os.ReadFile(filepath.Join(m.o.Root, workModeFile))
	cur := strings.TrimSpace(string(wm))
	if errors.Is(err, fs.ErrNotExist) {
		cur = "(missing)"
	}
	if m.workMode == nil {
		m.workMode = &cur
	}
	res = append(res, m.edge(WatchWorkMode, "work_mode", cur != *m.workMode,
		fmt.Sprintf("%s changed from %s to %s", workModeFile, *m.workMode, cur))...)

	return res
}

// smartipLog reports new smartipd alarm lines from logd's ring.
func (m *Manager) smartipLog(ctx context.Context) []Finding {
	lr := m.bin("logread")
	if !strings.HasPrefix(lr, "/") {
		m.note("no-logread", "logread not found: the smartipd log watch (R8b) is off")
		return nil
	}
	out, err := m.o.Run.Run(ctx, lr, "-l", logLines)
	if err != nil {
		m.note("logread-err", fmt.Sprintf("logread: %v (smartipd log watch skipped)", err))
		return nil
	}
	var res []Finding
	now := map[string]bool{}
	for _, l := range strings.Split(string(out), "\n") {
		if !strings.Contains(strings.ToLower(l), "smartip") || !smartipAlarm.MatchString(l) {
			continue
		}
		now[l] = true
		if !m.logSeen[l] {
			res = append(res, Finding{Kind: WatchSmartIP, Detail: strings.TrimSpace(l)})
		}
	}
	m.logSeen = now // lines that left the ring cannot come back
	return res
}

// hasInclude reports whether a uci firewall config has an include section
// whose path is p.
func hasInclude(conf []byte, p string) bool {
	in := false
	for _, l := range bytes.Split(conf, []byte("\n")) {
		f := strings.Fields(string(l))
		if len(f) == 0 {
			continue
		}
		switch {
		case f[0] == "config":
			in = len(f) >= 2 && f[1] == "include"
		case in && f[0] == "option" && len(f) >= 3 && f[1] == "path":
			if strings.Trim(f[2], `'"`) == p {
				return true
			}
		}
	}
	return false
}
