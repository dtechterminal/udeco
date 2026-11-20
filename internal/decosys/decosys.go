// Package decosys takes a rooted TP-Link Deco X20 away from TP-Link's own
// software so that the udeco-ap agent can own the unit (agent-design.md §3.2).
//
// A Manager stops the TP-Link services that would undo the agent's Wi-Fi
// configuration or talk to TP-Link's cloud, drops the procd config triggers
// that rebuild Wi-Fi (or reboot the unit), strips TP-Link's cron jobs, replaces
// the pool-based ntpd with one that only asks the gateway, and installs an
// egress firewall for the unit's own traffic and an inbound fence, UDECO-IN (ingress.go)
// in front of TP-Link's management ports.
//
// Each Enforce also watches for TP-Link state that comes back on its own
// (interference-audit.md §3): a second IPv4 address on br-lan (the lan
// default 192.168.0.1/22, which is the gateway's address) and a DHCP server
// on br-lan (watch.go), TP-Link's QoS htb on br-lan (qdisc.go), the stock
// reset-button handler (button.go), the crontab invariant (cron.go), and it
// holds off while a firmware upgrade or the boot chain runs (guard.go).
// What it finds after the takeover is reported in Report.Foreign and
// counted (Counts) so the agent can log drift.
//
// smartipd (R20) is kept: it runs the unit's own DHCP client, and replacing
// it needs the 24 h renew test on .205 (audit Q6). Until then its harmful
// outcomes are watched instead: the 192.168.0.1 alias is deleted, a udhcpd
// on br-lan is killed, and smartipd's disconnect/clear-ip/phy-power/restart
// log lines and 'wifi disconn*' or 'ethctl phy-power' children are reported.
//
// Safety rules (services.md §4 and its verifier notes) are encoded in what the
// package can do at all: it never stops a KEEP service (procd, ubusd, netifd,
// logd, login, crond, /data/dropbear, smartipd, udhcpc, hostapd,
// wpa_supplicant, eapd, apsd, imsnoop, powermanager, leds), never runs
// repacd, "wifi" or a network restart/reload, never touches tpbr or sysmode
// configuration, and never writes nvram. Every stop lasts until reboot only:
// /etc is a ramfs, and a reboot restores stock TP-Link behaviour.
//
// Every command goes through a Runner and every file access is relative to
// Options.Root, so tests run against a fake filesystem and a fake Runner.
package decosys

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

// Runner executes a command and returns its stdout. Implementations apply
// their own timeout. It is the same small interface the wl and bcmwifi
// packages use.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) ([]byte, error)
}

// Options configures a Manager.
type Options struct {
	// Root is the filesystem root: "/" on the device, a testdata tree in tests.
	Root string
	// Run executes commands on the device.
	Run Runner
	// ControllerIP is the UniFi controller's address. Egress allows it
	// explicitly when it lies outside LANCIDR.
	ControllerIP string
	// GatewayIP is the LAN gateway. It becomes the only NTP server; when it
	// is empty the Manager leaves ntpd alone. Egress allows it explicitly
	// when it lies outside LANCIDR.
	GatewayIP string
	// LANCIDR is the unit's own subnet, e.g. "192.168.0.0/24". Egress refuses
	// to install a drop rule without it. The inbound fence accepts SSH :22
	// from it when MgmtSources is empty.
	LANCIDR string
	// LANDev is the LAN bridge; "" means "br-lan".
	LANDev string
	// UnitIP is the unit's own DHCP lease on LANDev (the agent's identity
	// address). Every other IPv4 address on LANDev is deleted (R8a). When it
	// is empty, or not on LANDev at the time, only an address equal to
	// GatewayIP or ControllerIP is deleted.
	UnitIP string
	// MgmtSources are the only sources (IPv4/IPv6 addresses or CIDRs) allowed
	// to reach SSH :22 once set (R5). Empty means: accept :22 from LANCIDR
	// and never drop :22, so the user cannot be locked out by default.
	MgmtSources []string
	// ConsoleIP is the only source allowed to reach SSHDPort (the agent's
	// SSH-adopt listener). Empty leaves SSHDPort unfenced.
	ConsoleIP string
	// SSHDPort is the agent's SSH-adopt port; 0 means DefaultSSHDPort.
	SSHDPort int
	// LoopGuardFile is the agent's record (a device path, on ramfs) of the
	// Ethernet ports its loop guard took out of LANDev, one "<port> <why>"
	// per line. Restore puts each back into LANDev and removes the record.
	// Empty: Restore leaves the bridge ports alone.
	LoopGuardFile string
	// DryRun makes Enforce, Egress and Restore report what they would do
	// without changing anything. Read-only commands (ubus call service list,
	// iptables -S/-C) still run so the plan is accurate.
	DryRun bool
	// Logf receives one line per action. Nil discards.
	Logf func(string, ...any)
}

// Step kinds.
const (
	KindCron    = "cron"    // rewrite /etc/crontabs/root without TP-Link lines
	KindStop    = "stop"    // /etc/init.d/<name> stop (or a TP-Link group stop)
	KindTrigger = "trigger" // drop an instance-less procd service and its triggers
	KindKill    = "kill"    // SIGTERM a script-started daemon by PID
	KindNTP     = "ntp"     // stop TP-Link's ntpd or start the agent's ntpd
	KindAddr    = "addr"    // delete a foreign IPv4 address from br-lan (R8a)
	KindDHCPD   = "dhcpd"   // kill a DHCP server serving br-lan (R8)
	KindQdisc   = "qdisc"   // save and delete TP-Link's QoS root qdisc on br-lan (R24)
	KindButton  = "button"  // install the reset-button wrapper (R11)
)

// softKinds are the watch steps whose failure does not fail Enforce.
var softKinds = map[string]bool{KindAddr: true, KindDHCPD: true, KindQdisc: true, KindButton: true}

// Step is one action Enforce takes (or, with DryRun, would take).
type Step struct {
	Kind   string   // one of the Kind constants
	Target string   // init script, procd service, process or file the step acts on
	Reason string   // why the step is needed, for logs
	Cmd    []string // the command run; nil for a pure file rewrite
	Err    error    // set in Report when the step failed

	do func(ctx context.Context) error // executes the step; nil runs Cmd
}

// String renders the step for logs and DryRun output.
func (s Step) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s", s.Kind, s.Target)
	if len(s.Cmd) > 0 {
		fmt.Fprintf(&b, ": %s", strings.Join(s.Cmd, " "))
	}
	if s.Reason != "" {
		fmt.Fprintf(&b, " (%s)", s.Reason)
	}
	if s.Err != nil {
		fmt.Fprintf(&b, " FAILED: %v", s.Err)
	}
	return b.String()
}

// Report is the outcome of one Enforce.
type Report struct {
	Steps    []Step   // steps executed in order (planned only, with DryRun)
	DryRun   bool     // nothing was executed
	Warnings []string // things noticed but not acted on
	// Guard is what Enforce found in flight that it must not interfere
	// with (R17). Warnings carries the same, as text.
	Guard Guard
	// Foreign is the TP-Link state found this pass that the takeover had
	// already removed, or that is foreign whenever it appears (R10): one
	// Finding per re-asserted step after the first clean Enforce, plus the
	// watch results (addresses, DHCP servers, smartipd actions, the boot
	// hook, apsd/imsnoop/crond, work_mode). Watch conditions that persist
	// are reported when they appear and when they clear, not every pass.
	Foreign []Finding
}

// Finding is one piece of foreign state.
type Finding struct {
	Kind   string // a Kind constant for a step, else a Watch constant
	Detail string
	// Fixed is true when Enforce re-asserted the takeover state; false for
	// report-only findings and failed steps.
	Fixed bool
}

func (f Finding) String() string {
	s := f.Kind + ": " + f.Detail
	if f.Fixed {
		s += " (re-asserted)"
	}
	return s
}

// Changed reports whether Enforce had anything to do.
func (r Report) Changed() bool { return len(r.Steps) > 0 }

// Manager enforces the takeover. It is safe for concurrent use; calls are
// serialised.
type Manager struct {
	o   Options
	now func() time.Time

	mu sync.Mutex
	// allowTCP: extra egress destinations ("ip:port", sorted), the agent's
	// RadSec servers (egressallow.go); guarded by mu
	allowTCP []string
	// siteSSH: the site's device users may log in on SSHDPort from the
	// :22 sources (sitessh.go); guarded by mu
	siteSSH bool
	// locked: the last LoginLock(true) succeeded (loginlock.go); guarded
	// by mu
	locked bool
	// termMu guards termAt: when each still-running PID was first sent
	// SIGTERM by a kill step (killGrace).
	termMu sync.Mutex
	termAt map[int]time.Time
	// triggersClean is true once the procd trigger services were seen absent
	// (or deleted successfully) at triggersAt.
	triggersClean bool
	triggersAt    time.Time

	// tookOver is set by the first Enforce that returned no error; steps
	// after it are drift and become Findings.
	tookOver bool
	// counts holds cumulative Finding counts by kind (Counts).
	counts map[string]int
	// conds holds the watch conditions seen last pass (edge triggering).
	conds map[string]string
	// logSeen holds the smartip log lines already reported.
	logSeen map[string]bool
	// workMode is /tmp/work_mode at the first Enforce; imsnoopPID the last
	// imsnoop PID seen.
	workMode   *string
	imsnoopPID int
	// installed holds, per "<bin> <chain>", the rules this Manager last
	// installed, so a later repair with the same rules counts as a
	// re-insert (a changed configuration does not).
	installed map[string]string
	// noted holds one-time log notes (a missing binary).
	noted map[string]bool

	// beforeCronRename is a test hook run between writing the new crontab
	// and the re-read that guards against a lost append.
	beforeCronRename func()
}

// triggerRecheck bounds how long Enforce trusts that the procd trigger
// services are still gone without asking procd again. Processes coming back
// also force a recheck, because whatever re-ran TP-Link init scripts may have
// re-registered the triggers too.
const triggerRecheck = 10 * time.Minute

// New returns a Manager. Root defaults to "/".
func New(o Options) *Manager {
	if o.Root == "" {
		o.Root = "/"
	}
	if o.Logf == nil {
		o.Logf = func(string, ...any) {}
	}
	if o.LANDev == "" {
		o.LANDev = unit.LANBridge
	}
	if o.SSHDPort == 0 {
		o.SSHDPort = DefaultSSHDPort
	}
	return &Manager{o: o, now: time.Now, counts: map[string]int{}, conds: map[string]string{},
		logSeen: map[string]bool{}, installed: map[string]string{}, noted: map[string]bool{}}
}

// Counts returns how often each kind of foreign state was found since the
// Manager was made (R10): Finding kinds from Enforce, plus "ingress" and
// "egress" for firewall chains or jumps that had to be re-inserted. The map
// is a copy.
func (m *Manager) Counts() map[string]int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return maps.Clone(m.counts)
}

// found records a finding in rep and in the counters.
func (m *Manager) found(rep *Report, f Finding) {
	m.counts[f.Kind]++
	rep.Foreign = append(rep.Foreign, f)
}

// note logs msg once per key.
func (m *Manager) note(key, msg string) {
	if !m.noted[key] {
		m.noted[key] = true
		m.o.Logf("decosys: %s", msg)
	}
}

// Plan returns the steps Enforce would execute now, without executing any.
// It reads /proc and the crontab, runs the watches' read-only commands, and
// asks procd for its service list when the trigger state needs checking.
func (m *Manager) Plan(ctx context.Context) ([]Step, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	// The watches keep edge state; a plan must not consume it.
	conds, seen, wm, ims := maps.Clone(m.conds), maps.Clone(m.logSeen), m.workMode, m.imsnoopPID
	defer func() { m.conds, m.logSeen, m.workMode, m.imsnoopPID = conds, seen, wm, ims }()
	p, err := m.plan(ctx)
	return p.steps, err
}

// Enforce brings the unit to the takeover state and keeps it there. It is
// idempotent and cheap when nothing needs doing: one pass over /proc, a few
// small file reads, and three read-only commands for the watches ('ip -o -4
// addr show dev br-lan', 'tc qdisc show dev br-lan', 'logread -l 200'). The
// agent calls it once the boot gate (R1) is open and then every tick. A
// failed step does not stop later steps; all failures are joined in the
// returned error and marked in the Report. Report.Guard says what was in
// flight; Report.Foreign and Counts say what came back.
func (m *Manager) Enforce(ctx context.Context) (Report, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	p, perr := m.plan(ctx)
	rep := Report{DryRun: m.o.DryRun, Warnings: p.warnings, Guard: p.guard}
	for _, f := range p.findings {
		m.found(&rep, f)
	}
	if m.o.DryRun {
		rep.Steps = p.steps
		for _, s := range p.steps {
			m.o.Logf("decosys: dry-run: %s", s)
		}
		return rep, perr
	}

	errs := []error{perr}
	var stopped []string
	for _, s := range p.steps {
		if err := ctx.Err(); err != nil {
			errs = append(errs, err)
			break
		}
		s.Err = m.exec(ctx, s)
		if s.Err != nil {
			// A failed watch step is logged and reported (Foreign, Fixed
			// false) but does not fail Enforce: the agent waits for a
			// clean Enforce before it owns Wi-Fi, and none of these is a
			// precondition for that.
			if !softKinds[s.Kind] {
				errs = append(errs, fmt.Errorf("%s %s: %w", s.Kind, s.Target, s.Err))
			}
			m.o.Logf("decosys: %s", s)
		} else {
			m.o.Logf("decosys: done: %s", s)
			if s.Kind == KindStop || (s.Kind == KindNTP && s.Target == sysntpdInit) {
				stopped = append(stopped, s.Target)
			}
		}
		rep.Steps = append(rep.Steps, s)
		// Before the takeover these steps are the takeover itself. After
		// it, each one is TP-Link state that came back. Address, DHCP
		// server and button steps are foreign whenever they appear.
		if m.tookOver || s.Kind == KindAddr || s.Kind == KindDHCPD || s.Err != nil && softKinds[s.Kind] {
			m.found(&rep, Finding{Kind: s.Kind, Detail: s.Target + ": " + s.Reason, Fixed: s.Err == nil})
		}
	}
	if len(stopped) > 0 {
		if err := m.recordStopped(stopped); err != nil {
			errs = append(errs, err)
		}
	}
	if p.triggersChecked && p.triggersDone(rep.Steps) {
		m.triggersClean, m.triggersAt = true, m.now()
	}
	err := errors.Join(errs...)
	if err == nil {
		m.tookOver = true
	}
	return rep, err
}

// exec runs one step.
func (m *Manager) exec(ctx context.Context, s Step) error {
	if s.do != nil {
		return s.do(ctx)
	}
	_, err := m.o.Run.Run(ctx, s.Cmd[0], s.Cmd[1:]...)
	return err
}

// mutate runs a state-changing command, or only logs it under DryRun.
func (m *Manager) mutate(ctx context.Context, name string, args ...string) error {
	line := strings.TrimSpace(name + " " + strings.Join(args, " "))
	if m.o.DryRun {
		m.o.Logf("decosys: dry-run: %s", line)
		return nil
	}
	m.o.Logf("decosys: run: %s", line)
	_, err := m.o.Run.Run(ctx, name, args...)
	if err != nil {
		return fmt.Errorf("%s: %w", line, err)
	}
	return nil
}
