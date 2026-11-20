package decosys

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strconv"
	"time"
)

// plan is the result of one inspection of the unit.
type plan struct {
	steps    []Step
	warnings []string
	guard    Guard
	findings []Finding // report-only watch results
	// triggersChecked is true when procd's service list was read this pass,
	// so every remaining trigger service has a step in steps.
	triggersChecked bool
}

// triggersDone reports whether every planned trigger step is in done and
// succeeded. A pass cut short (cancelled context) leaves some unexecuted.
func (p plan) triggersDone(done []Step) bool {
	count := func(ss []Step, ok bool) int {
		n := 0
		for _, s := range ss {
			if s.Kind == KindTrigger && (!ok || s.Err == nil) {
				n++
			}
		}
		return n
	}
	return count(done, true) == count(p.steps, false)
}

// plan inspects the unit and returns the steps to reach the takeover state.
// Callers hold m.mu.
func (m *Manager) plan(ctx context.Context) (plan, error) {
	var p plan
	procs, err := m.readProcs()
	if err != nil {
		return p, fmt.Errorf("read /proc: %w", err)
	}
	var errs []error
	p.guard = m.guard(procs)
	p.warnings = p.guard.warnings()

	cron, err := m.cronStep()
	if err != nil {
		errs = append(errs, err)
	} else if cron != nil {
		p.steps = append(p.steps, *cron)
	}

	procdBack := false
	add := func(ts []target) {
		for _, t := range ts {
			s := m.targetSteps(t, procs)
			if len(s) > 0 && t.procd {
				procdBack = true
			}
			p.steps = append(p.steps, s...)
		}
	}
	// R14/R17: management first, but never while an upgrade is in flight
	// or the boot chain may still be starting it.
	if len(p.guard.Upgrade) == 0 && len(p.guard.Boot) == 0 {
		add(phaseFirst)
	}
	add(phaseRestarters)
	for _, t := range phaseDaemons {
		if t.procd && len(matching(t, procs)) > 0 {
			procdBack = true
		}
	}

	if !m.triggersClean || procdBack || m.now().Sub(m.triggersAt) >= triggerRecheck {
		ts, err := m.triggerSteps(ctx)
		if err != nil {
			errs = append(errs, err)
		} else {
			p.triggersChecked = true
			p.steps = append(p.steps, ts...)
		}
	}

	add(phaseDaemons)
	add(phaseKills)
	p.steps = append(p.steps, m.ntpSteps(procs)...)

	// Watches (watch.go, qdisc.go, button.go).
	// A watch that cannot read does not fail the pass; it is reported
	// (once, and again when it recovers).
	addr, notes, err := m.addrSteps(ctx)
	p.findings = append(p.findings, m.edge(WatchError, "err-addr", err != nil, fmt.Sprint(err))...)
	p.steps = append(p.steps, addr...)
	p.findings = append(p.findings, notes...)
	dh, notes2 := m.dhcpdSteps(procs)
	p.steps = append(p.steps, dh...)
	p.findings = append(p.findings, notes2...)
	q, notes3, err := m.qdiscSteps(ctx)
	p.findings = append(p.findings, m.edge(WatchError, "err-qdisc", err != nil, fmt.Sprint(err))...)
	p.steps = append(p.steps, q...)
	p.findings = append(p.findings, notes3...)
	if b := m.buttonStep(); b != nil {
		p.steps = append(p.steps, *b)
	}
	p.findings = append(p.findings, m.watch(ctx, procs)...)
	return p, errors.Join(errs...)
}

// matching returns the PIDs of the processes that belong to t.
func matching(t target, procs []proc) []int {
	var pids []int
	for _, pr := range procs {
		if t.matches(pr.argv) {
			pids = append(pids, pr.pid)
		}
	}
	return pids
}

// targetSteps returns the steps that stop t, or nil when it is not running.
func (m *Manager) targetSteps(t target, procs []proc) []Step {
	var pids []int
	for _, pr := range procs {
		if t.matches(pr.argv) && !protected(pr.argv) {
			pids = append(pids, pr.pid)
		}
	}
	if len(pids) == 0 {
		return nil
	}
	initPath := "/etc/init.d/" + t.init
	var steps []Step
	switch {
	case t.kill:
		return []Step{m.killStep(t.init, t.why, pids, t.matches)}
	case m.exists(initPath):
		args := t.stopArgs
		if args == nil {
			args = []string{"stop"}
		}
		steps = []Step{{Kind: KindStop, Target: t.init, Reason: t.why, Cmd: append([]string{initPath}, args...)}}
	case t.procd:
		// No init script: delete the procd service so it is not respawned.
		steps = []Step{{Kind: KindStop, Target: t.init, Reason: t.why + " (no init script)",
			Cmd: []string{m.bin("ubus"), "call", "service", "delete", ubusName(t.init)}}}
	default:
		return []Step{m.killStep(t.init, t.why+" (no init script)", pids, t.matches)}
	}
	if t.killRest {
		steps = append(steps, m.killStep(t.init, "leftover processes after stop", pids, t.matches))
	}
	return steps
}

// killGrace is how long a process may outlive a SIGTERM before a later pass
// sends SIGKILL.
const killGrace = 3 * time.Second

// killStep SIGTERMs those of pids that still run a process accepted by match
// when the step executes. The plan's PIDs can be stale by then (an earlier
// stop in the same pass reaped them, or the PID was reused), and a reused
// PID must never be signalled. A kill that fails only because the processes
// are already gone is not an error.
func (m *Manager) killStep(target, why string, pids []int, match func([]string) bool) Step {
	cmd := []string{m.bin("kill")}
	for _, pid := range pids {
		cmd = append(cmd, strconv.Itoa(pid))
	}
	s := Step{Kind: KindKill, Target: target, Reason: why, Cmd: cmd}
	s.do = func(ctx context.Context) error {
		live := m.stillRunning(pids, match)
		if len(live) == 0 {
			return nil
		}
		var args, hard []string
		now := m.now()
		m.termMu.Lock()
		if m.termAt == nil {
			m.termAt = map[int]time.Time{}
		}
		for _, pid := range live {
			if t0, ok := m.termAt[pid]; ok && now.Sub(t0) >= killGrace {
				hard = append(hard, strconv.Itoa(pid))
				continue
			}
			if _, ok := m.termAt[pid]; !ok {
				m.termAt[pid] = now
			}
			args = append(args, strconv.Itoa(pid))
		}
		m.termMu.Unlock()
		var err error
		if len(hard) > 0 {
			// Still running killGrace after a SIGTERM: it ignores or
			// handles SIGTERM (cloud-proxy on .205 does).
			m.o.Logf("decosys: %s: SIGKILL %v (survived SIGTERM for %v)", target, hard, killGrace)
			_, err = m.o.Run.Run(ctx, cmd[0], append([]string{"-9"}, hard...)...)
		}
		if len(args) > 0 {
			if _, e := m.o.Run.Run(ctx, cmd[0], args...); e != nil {
				err = e
			}
		}
		if err != nil && len(m.stillRunning(live, match)) > 0 {
			return err
		}
		return nil
	}
	return s
}

// stillRunning returns the pids whose current command line match accepts.
func (m *Manager) stillRunning(pids []int, match func([]string) bool) []int {
	var live []int
	for _, pid := range pids {
		if argv := m.cmdline(pid); argv != nil && match(argv) && !protected(argv) {
			live = append(live, pid)
		}
	}
	return live
}

// triggerSteps asks procd which trigger services are registered and returns
// one delete step for each.
func (m *Manager) triggerSteps(ctx context.Context) ([]Step, error) {
	out, err := m.o.Run.Run(ctx, m.bin("ubus"), "call", "service", "list")
	if err != nil {
		return nil, fmt.Errorf("ubus call service list: %w", err)
	}
	var svcs map[string]json.RawMessage
	if err := json.Unmarshal(out, &svcs); err != nil {
		return nil, fmt.Errorf("ubus call service list: %w", err)
	}
	var steps []Step
	for _, name := range triggerServices {
		if _, ok := svcs[name]; ok {
			steps = append(steps, Step{Kind: KindTrigger, Target: name,
				Reason: "procd config trigger rebuilds Wi-Fi or reboots",
				Cmd:    []string{m.bin("ubus"), "call", "service", "delete", ubusName(name)}})
		}
	}
	return steps, nil
}

// ubusName returns the JSON argument {"name":n}.
func ubusName(n string) string {
	b, _ := json.Marshal(map[string]string{"name": n})
	return string(b)
}

// rebuilding reports whether a process is a TP-Link Wi-Fi rebuild in flight
// (Guard.Rebuild). It is reported, never killed: interrupting repacd half way
// could leave the radios down.
func rebuilding(argv []string) bool {
	for _, a := range argv {
		if a == "/etc/init.d/repacd" || a == "/sbin/wifi" {
			return true
		}
	}
	return path.Base(argv[0]) == "repacd"
}

// BinDirs is where firmware binaries live, searched in order. The agent's
// PATH is these, joined (cmd/udeco-ap agentPATH).
var BinDirs = []string{"/usr/sbin", "/usr/bin", "/sbin", "/bin"}

// bin returns the absolute device path of a firmware binary, so commands do
// not depend on the agent's PATH, or the bare name when it is not found.
func (m *Manager) bin(name string) string {
	for _, d := range BinDirs {
		if p := d + "/" + name; m.exists(p) {
			return p
		}
	}
	return name
}
