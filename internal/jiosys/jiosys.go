// SPDX-License-Identifier: GPL-2.0-or-later

// Package jiosys is the agent's system manager on a JioFiber JCOW414 used
// as a plain access point (platform "jio-mtk"). It does what decosys does
// on a Deco only as far as this unit needs it: it keeps Jio's management
// services down (the owner's boot script, /flash2/pfrm2.0/etc/customInit,
// kills them once at boot, but dms, ras, captivePortald and the service
// hosts start after it and ignore SIGTERM). It installs no firewall and
// never restarts a Jio service: telnet stays as it is (the web UI is kept
// down too), and
// a hand-back leaves the unit as the owner's script wants it.
package jiosys

import (
	"context"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/decosys"
)

// DefaultKeepDown is the owner's KILL_ONT_PATTERNS (customInit): the Jio
// ONT/WAN management, remote management (dms, ras), the captive portal,
// the scanners and the mesh. Verified 2026-11-19 on the Garage AP: killing
// each of these leaves the bridge, its address, the gateway, Wi-Fi,
// dnsmasq, lighttpd, telnetd and tcapi (svchost cfg.svc) working.
var DefaultKeepDown = []string{"omci", "ponmgr", "ont_dc", "ont_stb_bind", "dms", "ras", "dimclient",
	"igmptable_sig", "captivePortald", "qosMain", "nscand", "smartcableONTApp", "runsmartcableONTApp",
	"pon.svc", "wan.svc", "wan_related.svc", "central_ctrl.svc", "other.svc", "voip.svc", "mesh.svc", "easyMeshd",
	"lighttpd"} // the web UI: the owner asked for it down too (2026-11-19)

// DefaultKeepOnly is the dumb-AP set (the owner, 2026-11-19: "stop
// everything except telnet"): init, telnet, the serial console, the agent
// and its supervisor, and the owner's boot script while it runs. Whatever
// these started (telnet sessions, the agent's commands) stays too. The
// radios need no daemon: their firmware is in the drivers (no
// /lib/firmware, no hotplug helper); the bridge, address and routes are
// kernel state. syslogd stays because init respawns it (inittab).
var DefaultKeepOnly = []string{"init", "telnetd", "getty", "syslogd", "udeco-ap", "/flash2/udeco/start.sh", "customInit"}

// protected are never signalled, whatever the patterns say.
var protected = []string{"telnetd", "getty", "init", "udeco-ap", "cfg.svc", "dnsmasq"}

// KindStop is the decosys step kind of a process stopped here.
const KindStop = "stop-jio"

// Options configures a Manager.
type Options struct {
	Root     string   // "/" on the device; a test tree in tests
	KeepDown []string // nil = DefaultKeepDown
	// KeepOnly, when set, stops every userland process except those
	// matching an entry (program name, an argument's base name, or an
	// argument equal to an entry holding a "/") and their descendants.
	// KeepDown is then unused.
	KeepOnly []string
	Logf     func(string, ...any)
	// kill and self are test hooks.
	kill func(pid int, sig syscall.Signal) error
	self int
}

// Manager keeps the listed processes down.
type Manager struct {
	o       Options
	mu      sync.Mutex
	termed  map[int]time.Time // pids sent SIGTERM, for SIGKILL on the next pass
	stopped int               // processes stopped since start
	now     func() time.Time
}

// New returns a Manager. Nothing changes until Enforce.
func New(o Options) *Manager {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.KeepDown == nil {
		o.KeepDown = DefaultKeepDown
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.kill == nil {
		o.kill = syscall.Kill
	}
	if o.self == 0 {
		o.self = os.Getpid()
	}
	return &Manager{o: o, termed: map[int]time.Time{}, now: time.Now}
}

// match reports which pattern argv matches: the program's base name equals
// or starts with the pattern, or an argument's base name equals it (the
// service hosts: "svchost -c /etc/mesh.svc"). Substring matching, as the
// owner's `ps | grep` does, would also hit unrelated programs ("ras").
func match(argv []string, patterns []string) string {
	if len(argv) == 0 {
		return ""
	}
	prog := path.Base(argv[0])
	for _, p := range protected {
		if prog == p {
			return ""
		}
		for _, a := range argv[1:] {
			if path.Base(a) == p {
				return ""
			}
		}
	}
	for _, p := range patterns {
		if prog == p || strings.HasPrefix(prog, p) && len(p) > 3 {
			return p
		}
		for _, a := range argv[1:] {
			if path.Base(a) == p {
				return p
			}
		}
	}
	return ""
}

type proc struct {
	pid, ppid int
	argv      []string
}

// keeps reports whether argv matches a KeepOnly entry.
func keeps(argv []string, list []string) bool {
	if len(argv) == 0 {
		return false
	}
	prog := path.Base(argv[0])
	for _, k := range list {
		if prog == k {
			return true
		}
		for _, a := range argv[1:] {
			if a == k || !strings.Contains(k, "/") && path.Base(a) == k {
				return true
			}
		}
	}
	return false
}

// ppidOf reads the parent pid from /proc/<pid>/stat (0 when unknown).
func ppidOf(b []byte) int {
	s := string(b)
	i := strings.LastIndexByte(s, ')')
	if i < 0 {
		return 0
	}
	f := strings.Fields(s[i+1:])
	if len(f) < 2 {
		return 0
	}
	n, _ := strconv.Atoi(f[1])
	return n
}

func (m *Manager) procs() ([]proc, error) {
	ents, err := os.ReadDir(filepath.Join(m.o.Root, "proc"))
	if err != nil {
		return nil, err
	}
	var out []proc
	for _, e := range ents {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 1 || pid == m.o.self || pid == os.Getppid() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(m.o.Root, "proc", e.Name(), "cmdline"))
		if err != nil || len(b) == 0 {
			continue // kernel thread or gone
		}
		argv := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
		st, _ := os.ReadFile(filepath.Join(m.o.Root, "proc", e.Name(), "stat"))
		out = append(out, proc{pid: pid, ppid: ppidOf(st), argv: argv})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].pid < out[j].pid })
	return out, nil
}

// Enforce sends SIGTERM to every listed process and SIGKILL to those still
// there from an earlier pass (dms, ras and the service hosts ignore
// SIGTERM). Each signal is a Step; a process that comes back is Foreign.
func (m *Manager) Enforce(ctx context.Context) (decosys.Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var rep decosys.Report
	ps, err := m.procs()
	if err != nil {
		return rep, err
	}
	var kept map[int]bool
	if m.o.KeepOnly != nil {
		kept = m.keptSet(ps)
	}
	alive := map[int]bool{}
	for _, p := range ps {
		var pat string
		if kept != nil {
			if kept[p.pid] {
				continue
			}
			pat = path.Base(p.argv[0])
		} else if pat = match(p.argv, m.o.KeepDown); pat == "" {
			continue
		}
		alive[p.pid] = true
		sig, why := syscall.SIGTERM, "Jio service kept down while UniFi manages the AP"
		if kept != nil {
			why = "dumb AP: only telnet and the agent run"
		}
		if _, ok := m.termed[p.pid]; ok {
			sig, why = syscall.SIGKILL, "ignored SIGTERM"
		}
		st := decosys.Step{Kind: KindStop, Target: strings.Join(p.argv, " "), Reason: why,
			Cmd: []string{"kill", "-" + strconv.Itoa(int(sig)), strconv.Itoa(p.pid)}}
		if err := m.o.kill(p.pid, sig); err != nil {
			st.Err = err
		}
		if sig == syscall.SIGTERM {
			m.termed[p.pid] = m.now()
			if m.stopped > 0 {
				rep.Foreign = append(rep.Foreign, decosys.Finding{Kind: KindStop, Detail: pat + " is running again", Fixed: true})
			}
		} else {
			delete(m.termed, p.pid)
			m.stopped++
		}
		rep.Steps = append(rep.Steps, st)
	}
	for pid := range m.termed {
		if !alive[pid] {
			delete(m.termed, pid)
			m.stopped++
		}
	}
	for _, s := range rep.Steps {
		if s.Err != nil {
			err = fmt.Errorf("%s: %v", s.Target, s.Err)
		}
	}
	return rep, err
}

// keptSet is the KeepOnly roots and every process descended from one.
func (m *Manager) keptSet(ps []proc) map[int]bool {
	parent := map[int]int{}
	kept := map[int]bool{m.o.self: true, os.Getppid(): true}
	for _, p := range ps {
		parent[p.pid] = p.ppid
		if keeps(p.argv, m.o.KeepOnly) {
			kept[p.pid] = true
		}
	}
	for _, p := range ps {
		for q, n := p.ppid, 0; q > 1 && n < 64; q, n = parent[q], n+1 {
			if kept[q] {
				kept[p.pid] = true
				break
			}
		}
	}
	return kept
}

// Egress, Ingress, Restore, RestoreLoopGuard and FlushFlows change nothing:
// the unit keeps its own firewall, its bridge has no loop guard records and
// no flow cache. Restore leaves the Jio services down (the owner's choice).
func (m *Manager) Egress(context.Context, bool) error                  { return nil }
func (m *Manager) Ingress(context.Context, bool) error                 { return nil }
func (m *Manager) Restore(context.Context) error                       { return nil }
func (m *Manager) RestoreLoopGuard(context.Context) error              { return nil }
func (m *Manager) SetLAN(decosys.LAN) bool                             { return false }
func (m *Manager) FlushFlows(context.Context, decosys.FlowScope) error { return nil }

// Counts is the self-check's tally.
func (m *Manager) Counts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return map[string]int{"jio-stopped": m.stopped}
}
