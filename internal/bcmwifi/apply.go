// SPDX-License-Identifier: GPL-2.0-or-later

package bcmwifi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Apply runs p and verifies the result within Options.VerifyTimeout. If a
// step fails or verification does not pass, it rolls back (see Rollback)
// and returns the error. Only after a verified apply does it save
// p.Desired as last-good. With DryRun it logs the steps and changes nothing.
//
// Before the first change of a boot, while TP-Link's hostapd still runs,
// Apply records TP-Link's Wi-Fi state in RunDir/tplink-baseline.json so
// Rollback can hand Wi-Fi back exactly. If that capture fails, Apply
// changes nothing.
//
// A Desired whose apply failed (and was rolled back) is remembered: Apply
// refuses that identical Desired with ErrDesiredFailed, changing nothing,
// until a different Desired applies, or ForgetFailed. A failure caused by
// ctx (cancelled or past its deadline) is not remembered.
func (a *Applier) Apply(ctx context.Context, p Plan) error {
	if a.o.DryRun {
		a.logPlan("dry-run", p)
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	sum := desiredSum(p.Desired)
	if f := a.failed; f != nil && f.sum == sum {
		return fmt.Errorf("%w (it failed at %s: %v)", ErrDesiredFailed, f.at.Format(time.RFC3339), f.err)
	}
	if p.takeover && !a.exists(a.baselinePath()) {
		if err := a.captureBaseline(ctx); err != nil {
			return fmt.Errorf("bcmwifi: capture TP-Link baseline (nothing changed): %w", err)
		}
	}
	err := a.execute(ctx, p.Steps)
	if err == nil {
		err = a.verifyWait(ctx, p.Desired)
	}
	if err == nil {
		a.failed = nil
		d := p.Desired.clone()
		a.applied = &d
		a.saveSlots(a.layout(d)) // slots.go: the placement in force
		if serr := a.saveLastGood(d); serr != nil {
			a.o.Logf("bcmwifi: applied, but saving last-good failed: %v", serr)
		}
		a.shapeAfterApply(ctx, d)
		return nil
	}
	a.o.Logf("bcmwifi: apply failed: %v; rolling back", err)
	if ctx.Err() == nil {
		a.failed = &failedApply{sum: sum, err: err, at: time.Now()}
	}
	// The rollback must run even when ctx is what failed the apply
	// (shutdown, request deadline): with a cancelled ctx every command
	// would fail at once and leave TP-Link's hostapd stopped and ours not
	// started, i.e. no Wi-Fi until a reboot.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), rollbackTimeout)
	defer cancel()
	if rerr := a.rollback(rctx, &p.Desired); rerr != nil {
		return fmt.Errorf("bcmwifi: apply: %w; rollback: %v", err, rerr)
	}
	return fmt.Errorf("bcmwifi: apply: %w (rolled back)", err)
}

// failedApply identifies the Desired of the last failed Apply by a hash
// (the Desired itself holds secrets).
type failedApply struct {
	sum [32]byte
	err error
	at  time.Time
}

// desiredSum hashes d (JSON: map keys sorted, so stable) including its
// secrets, so a changed passphrase is a different Desired. Memory only.
func desiredSum(d Desired) [32]byte {
	b, _ := json.Marshal(d)
	return sha256.Sum256(append([]byte("udeco-desired:"), b...))
}

// ForgetFailed drops the memory of a failed Desired, so the next Apply of
// it runs again (for an operator retry, or after the agent's own backoff).
func (a *Applier) ForgetFailed() {
	a.mu.Lock()
	a.failed = nil
	a.mu.Unlock()
}

// Rollback restores the last-good state from StateDir and verifies it. If
// there is no last-good state, or it fails too, it hands Wi-Fi back to
// TP-Link. A radio whose TP-Link hostapd still runs (found by its pid file,
// else by /proc/<pid>/cmdline naming /tmp/wlN.1_hapd.conf or
// /tmp/wlN_hapd.conf) is left alone, except that a missing pid file is
// rewritten and its vifs' BSS and bridge state is re-asserted from the
// baseline; restarting a hostapd that runs is never attempted (a second one
// with the same -P fails and deletes the running one's pid file, live fact
// F7). On every other radio:
//
//  1. lower every vif that exists, then stop the agent's hostapd (its bss=
//     vifs are deleted when it exits, F2; only wlN1 survives) and take the
//     survivors out of the agent's bridges;
//  2. (all radios) delete the agent's br-v<vid> bridges and their
//     <uplink>.<vid> devices, and remove the agent's confs, pid,
//     driver-state and ACL files, its guest ebtables chains and its tc
//     rate-limit trees;
//  3. from RunDir/tplink-baseline.json (captured at takeover in this boot):
//     restore the radio's country, bw_cap, chanspec and txpwr_degrade if
//     they differ, make sure the radio is up (a failed apply may have
//     stopped between `wl down` and `wl up`), and restore the primary's MAC
//     filter;
//  4. restart TP-Link's hostapd with its own argv as captured (normally
//     `hostapd -B -P /tmp/wlN.1_hapd.pid /tmp/wlN.1_hapd.conf`,
//     /tmp/wlN_hapd.* on a master), using TP-Link's untouched conf, and wait
//     (up to 15 s, best effort) for it to recreate its bss= vifs;
//  5. restore each recreated vif's dwds, closednet, ap_isolate,
//     bss_maxassoc, wmf_bss_enable, rrm, rrm_nbr_scan, fbt, fbt_mdid,
//     fbt_ap, macmode and MAC list, and its rateset (the backhaul wlN1 gets
//     TP-Link's dwds 1, closednet 1, bss_maxassoc 16 when the baseline lacks
//     them), then, as TP-Link's wifi script does after starting hostapd
//     (which leaves every BSS down and unbridged, F3): ifconfig up and
//     `wl bss up` for each vif the baseline recorded up, `bss down` for the
//     others, and brctl addif for each vif it recorded bridged.
//
// The hand-back is best effort: every step runs even when an earlier one
// fails, and the first failure is returned. Steps on a vif that does not
// exist are nothing to do.
//
// Without a baseline (RunDir lost within a boot) step 3 is only "radio up",
// step 5 only the wlN1 backhaul defaults: TP-Link's hostapd is restarted
// from /tmp/wlN.1_hapd.conf or /tmp/wlN_hapd.conf where it is not running,
// its vifs stay BSS down, and ErrNoBaseline is returned; reboot for a full
// restore. Rollback does not restart TP-Link's daemons (awnd, repacd,
// triggers, cron): the agent does that with decosys.Restore.
func (a *Applier) Rollback(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.o.DryRun {
		if lg, err := a.loadLastGood(); err == nil && lg != nil {
			p, err := a.plan(ctx, *lg)
			if err == nil {
				a.logPlan("dry-run rollback to last-good", p)
				return nil
			}
		}
		st, _, err := a.handbackSteps(ctx)
		a.logPlan("dry-run hand back to TP-Link", Plan{Steps: st})
		return err
	}
	return a.rollback(ctx, nil)
}

// rollbackTimeout bounds the rollback Apply runs after a failure: a
// last-good apply plus its verification, then a hand-back.
const rollbackTimeout = 3 * time.Minute

// rollback restores last-good unless it equals failed, else hands back.
func (a *Applier) rollback(ctx context.Context, failed *Desired) error {
	lg, err := a.loadLastGood()
	if err != nil {
		a.o.Logf("bcmwifi: last-good unreadable: %v", err)
	}
	if lg != nil && (failed == nil || !sameDesired(*lg, *failed)) {
		a.o.Logf("bcmwifi: rolling back to last-good")
		p, err := a.plan(ctx, *lg)
		if err == nil {
			if err = a.execute(ctx, p.Steps); err == nil {
				if err = a.verifyWait(ctx, *lg); err == nil {
					a.applied = lg
					a.saveSlots(a.layout(*lg))
					a.shapeAfterApply(ctx, *lg)
					return nil
				}
			}
		}
		a.o.Logf("bcmwifi: last-good did not come up (%v); handing Wi-Fi back to TP-Link", err)
	}
	return a.handback(ctx)
}

// shapeAfterApply brings the rate limits to d once d is live. A failure is
// logged, not an apply failure: Wi-Fi works, and Tick retries.
func (a *Applier) shapeAfterApply(ctx context.Context, d Desired) {
	if _, err := a.syncShaping(ctx, a.layout(d)); err != nil {
		a.o.Logf("bcmwifi: applied, but rate limits: %v", err)
	}
}

func sameDesired(x, y Desired) bool {
	bx, _ := json.Marshal(x)
	by, _ := json.Marshal(y)
	return bytes.Equal(bx, by)
}

func (a *Applier) logPlan(prefix string, p Plan) {
	for _, n := range p.Notes {
		a.o.Logf("bcmwifi %s: note: %s", prefix, n)
	}
	for i, s := range p.Steps {
		a.o.Logf("bcmwifi %s: %d %s", prefix, i+1, s)
	}
}

// executeAll runs every step even when some fail (the hand-back is the
// last resort: a failed restore of one iovar must not keep TP-Link's
// hostapd from restarting). It returns the first non-optional failure.
func (a *Applier) executeAll(ctx context.Context, steps []Step) error {
	var first error
	for i, s := range steps {
		a.o.Logf("bcmwifi: %s", s)
		if err := a.do(ctx, s); err != nil {
			a.o.Logf("bcmwifi: step failed, continuing: %v", err)
			if !s.Optional && first == nil {
				first = fmt.Errorf("step %d (%s): %w", i+1, s.Desc, err)
			}
		}
	}
	return first
}

// execute runs steps in order. A failing optional step is logged; any other
// failure stops execution.
func (a *Applier) execute(ctx context.Context, steps []Step) error {
	for i, s := range steps {
		if err := ctx.Err(); err != nil {
			return err
		}
		a.o.Logf("bcmwifi: %s", s)
		if err := a.do(ctx, s); err != nil {
			if s.Optional {
				a.o.Logf("bcmwifi: optional step failed: %v", err)
				continue
			}
			return fmt.Errorf("step %d (%s): %w", i+1, s.Desc, err)
		}
	}
	return nil
}

func (a *Applier) run(ctx context.Context, argv ...string) error {
	out, err := a.o.Run.Run(ctx, argv[0], argv[1:]...)
	if err != nil {
		if msg := strings.TrimSpace(string(out)); msg != "" {
			return fmt.Errorf("%s: %w: %s", argv[0], err, firstLine(msg))
		}
		return fmt.Errorf("%s: %w", argv[0], err)
	}
	return nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// do runs one step. A step marked IfPresent whose vif does not exist has
// nothing to do: before it runs, or when it failed because the vif vanished
// meanwhile ("wl driver adapter not found", "No such device").
func (a *Applier) do(ctx context.Context, s Step) error {
	if v := s.IfPresent; v != "" && !a.netdevExists(v) {
		a.o.Logf("bcmwifi: %s absent: nothing to do", v)
		return nil
	}
	err := a.doStep(ctx, s)
	if err != nil && s.IfPresent != "" && !a.netdevExists(s.IfPresent) && absentErr(err) {
		a.o.Logf("bcmwifi: %s vanished: nothing to do", s.IfPresent)
		return nil
	}
	return err
}

// absentErr reports the errors wl, ifconfig and brctl give for a missing
// netdev.
func absentErr(err error) bool {
	m := err.Error()
	return strings.Contains(m, "adapter not found") || strings.Contains(m, "No such device") || strings.Contains(m, "does not exist")
}

func (a *Applier) doStep(ctx context.Context, s Step) error {
	switch s.Kind {
	case StepCmd:
		return a.run(ctx, s.Argv...)
	case StepWrite:
		return writeFileAtomic(a.fsPath(s.Path), s.Data, s.Mode)
	case StepRemove:
		if err := os.Remove(a.fsPath(s.Path)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	case StepStop:
		return a.stopPid(ctx, s.Path, s.Proc, s.Match)
	case StepWait:
		return a.waitHostapd(ctx, s)
	case StepBridgeAdd:
		cur := a.bridgeOf(s.Port)
		if cur == s.Bridge {
			return nil
		}
		if cur != "" {
			if err := a.run(ctx, "brctl", "delif", cur, s.Port); err != nil {
				return err
			}
		}
		return a.run(ctx, "brctl", "addif", s.Bridge, s.Port)
	case StepBridgeDel:
		if cur := a.bridgeOf(s.Port); cur != "" {
			return a.run(ctx, "brctl", "delif", cur, s.Port)
		}
		return nil
	case StepPut:
		f, err := os.OpenFile(a.fsPath(s.Path), os.O_WRONLY|os.O_TRUNC, 0)
		if err != nil {
			return err
		}
		if _, err := f.Write(s.Data); err != nil {
			f.Close()
			return err
		}
		return f.Close()
	}
	return fmt.Errorf("unknown step kind %d", s.Kind)
}

// stopPid sends SIGTERM to the process in pidFile if it is alive and named
// proc (else to the proc whose command line has the argument match, when
// match is set: a failed second hostapd with the same -P deletes the pid
// file of the running one, live fact F7), waits up to 3 s, then SIGKILLs it.
func (a *Applier) stopPid(ctx context.Context, pidFile, proc, match string) error {
	pid, alive := a.pidAlive(pidFile, proc)
	if !alive && match != "" {
		pid, alive = a.findProc(proc, match)
	}
	if !alive {
		return nil
	}
	wait := func(n int) bool {
		for i := 0; i < n; i++ {
			if !a.procAlive(pid, proc) {
				return true
			}
			a.sleep(100 * time.Millisecond)
		}
		return !a.procAlive(pid, proc)
	}
	if err := a.run(ctx, "kill", strconv.Itoa(pid)); err != nil && a.procAlive(pid, proc) {
		return err
	}
	if wait(30) {
		return nil
	}
	_ = a.run(ctx, "kill", "-9", strconv.Itoa(pid))
	if wait(10) {
		return nil
	}
	return fmt.Errorf("%s (pid %d) did not exit", proc, pid)
}

// hostapd finishes its BSS setup after `hostapd -B` has returned: the bss=
// vifs appear, and the driver sets every BSS down, a moment later (the
// hand-back on .205 found wl02 missing right after the restart). Steps that
// configure, bridge or raise those vifs wait for it.
const (
	hapdWaitTimeout = 15 * time.Second
	hapdWaitPoll    = 200 * time.Millisecond
)

// waitHostapd waits until s.Ifaces exist and, with s.Path, until hostapd
// reports state=ENABLED on s.Port.
func (a *Applier) waitHostapd(ctx context.Context, s Step) error {
	var why string
	for i := 0; ; i++ {
		why = ""
		for _, v := range s.Ifaces {
			if !a.netdevExists(v) {
				why = v + " does not exist"
				break
			}
		}
		if why == "" && s.Path != "" {
			out, err := a.o.Run.Run(ctx, "hostapd_cli", "-p", s.Path, "-i", s.Port, "status")
			if err != nil || !strings.Contains(string(out), "state=ENABLED") {
				why = s.Port + " not ENABLED"
			}
		}
		if why == "" {
			if i > 0 {
				a.o.Logf("bcmwifi: hostapd ready after ~%s", time.Duration(i)*hapdWaitPoll)
			}
			return nil
		}
		if time.Duration(i)*hapdWaitPoll >= hapdWaitTimeout || ctx.Err() != nil {
			return fmt.Errorf("hostapd setup not finished after %s: %s", hapdWaitTimeout, why)
		}
		a.sleep(hapdWaitPoll)
	}
}

// writeFileAtomic writes data to full via a temp file and rename.
func writeFileAtomic(full string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(full)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-"+filepath.Base(full)+"-")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

// VerifyError lists what Verify found wrong.
type VerifyError struct{ Problems []string }

func (e *VerifyError) Error() string {
	return "bcmwifi: verify: " + strings.Join(e.Problems, "; ")
}

// Verify checks, once, that d is live: no TP-Link hostapd; the agent's
// hostapd answers PING on every radio with SSIDs; every placed SSID's vif
// is bss up, carries the SSID and is in its bridge; every other vif that
// exists (the hostapd placeholder wlN1 included) is bss down; every guest vif is behind
// the guest ebtables chains. A driver fbt state that does not read back as 1
// for an 802.11r SSID, a dwds that does not read back as 0, and (with
// MinRates) a rateset that does not read back as set are logged, not
// failed: the driver may ignore these iovars (see the wifi-bringup verifier
// notes), and Tick re-checks dwds.
func (a *Applier) Verify(ctx context.Context, d Desired) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.verify(ctx, d)
}

func (a *Applier) verifyWait(ctx context.Context, d Desired) error {
	n := int(a.o.VerifyTimeout / a.poll)
	for i := 0; ; i++ {
		err := a.verify(ctx, d)
		if err == nil || i >= n {
			return err
		}
		if ctx.Err() != nil {
			return err
		}
		a.sleep(a.poll)
	}
}

func (a *Applier) verify(ctx context.Context, d Desired) error {
	l := a.layout(d)
	var probs []string
	bad := func(f string, args ...any) { probs = append(probs, fmt.Sprintf(f, args...)) }
	for _, rl := range l.Radios {
		p := rl.Primary
		if !a.netdevExists(p) {
			continue
		}
		if tp, ok := a.tplinkHostapd(p); ok {
			bad("TP-Link hostapd still running (pid %d, %s)", tp.Pid, tp.Conf)
		}
		if len(rl.Used) > 0 {
			if _, ok := a.ourHostapd(p); !ok {
				bad("hostapd for %s not running", p)
			} else if out, err := a.o.Run.Run(ctx, "hostapd_cli", "-p", CtrlDir, "-i", rl.Used[0].Vif, "ping"); err != nil || !strings.Contains(string(out), "PONG") {
				bad("hostapd for %s does not answer ping", p)
			}
		}
		for _, v := range rl.Vifs {
			u, used := findUsed(rl, v)
			if !used && !a.netdevExists(v) {
				continue // a bss= vif no hostapd serves does not exist
			}
			bss, err := a.wlGet(ctx, v, "bss")
			if !used {
				if err != nil || bss != "down" {
					bad("unused %s is not down (%q)", v, bss)
				}
				continue
			}
			if err != nil || bss != "up" {
				bad("%s bss is %q, want up", v, bss)
			}
			if out, err := a.wlGet(ctx, v, "ssid"); err != nil || !ssidMatches(out, u.SSID.SSID) {
				bad("%s does not carry SSID %q", v, u.SSID.SSID)
			}
			if br := a.bridgeOf(v); br != u.Bridge {
				bad("%s is in bridge %q, want %q", v, br, u.Bridge)
			}
			if u.SSID.FT {
				if out, err := a.wlGet(ctx, v, "fbt"); err != nil || strings.TrimSpace(out) != "1" {
					a.o.Logf("bcmwifi: warning: %s driver fbt reads %q, 802.11r may not work", v, out)
				}
			}
			if out, err := a.wlGet(ctx, v, "dwds"); err != nil || strings.TrimSpace(out) != "0" {
				a.o.Logf("bcmwifi: warning: %s driver dwds reads %q, want 0 (WDS peers could join)", v, out)
			}
			if a.o.MinRates {
				if want, _ := ssidRateset(u.SSID, u.Band); len(want) > 0 {
					if out, err := a.wlGet(ctx, v, "rateset"); err != nil || parseRateset(out) != strings.Join(want, " ") {
						a.o.Logf("bcmwifi: warning: %s rateset reads %q, want %q (minimum rate not in force)", v, parseRateset(out), strings.Join(want, " "))
					}
				}
			}
		}
	}
	probs = append(probs, a.guestVerify(ctx, l)...)
	if len(probs) > 0 {
		return &VerifyError{Problems: probs}
	}
	return nil
}

// ssidMatches compares wl's `Current SSID: "..."` with want, formatted the
// way wl formats SSIDs (backslash doubled, non-printables as \xNN).
func ssidMatches(out, want string) bool {
	i, j := strings.IndexByte(out, '"'), strings.LastIndexByte(out, '"')
	if i < 0 || j <= i {
		return false
	}
	got := out[i+1 : j]
	var up, lo strings.Builder
	for k := 0; k < len(want); k++ {
		c := want[k]
		switch {
		case c == '\\':
			up.WriteString(`\\`)
			lo.WriteString(`\\`)
		case c >= 0x20 && c < 0x7f:
			up.WriteByte(c)
			lo.WriteByte(c)
		default:
			fmt.Fprintf(&up, `\x%02X`, c)
			fmt.Fprintf(&lo, `\x%02x`, c)
		}
	}
	return got == up.String() || got == lo.String()
}

// last-good state.

func (a *Applier) lastGoodPaths() (pub, sec string) {
	return path.Join(a.o.StateDir, "last-good.json"), path.Join(a.o.StateDir, "last-good.secrets.json")
}

// saveLastGood writes d to StateDir, secrets to a separate 0600 file. Files
// whose content is unchanged are not rewritten (StateDir is flash).
func (a *Applier) saveLastGood(d Desired) error {
	pub, sec := splitSecrets(d)
	pb, err := json.MarshalIndent(pub, "", " ")
	if err != nil {
		return err
	}
	sb, err := json.MarshalIndent(sec, "", " ")
	if err != nil {
		return err
	}
	pubPath, secPath := a.lastGoodPaths()
	if !a.sameFile(secPath, sb) {
		if err := writeFileAtomic(a.fsPath(secPath), sb, 0o600); err != nil {
			return err
		}
	}
	if !a.sameFile(pubPath, pb) {
		return writeFileAtomic(a.fsPath(pubPath), pb, 0o644)
	}
	return nil
}

// loadLastGood returns the saved last-good Desired, or nil if none.
func (a *Applier) loadLastGood() (*Desired, error) {
	pubPath, secPath := a.lastGoodPaths()
	pb, err := a.readFile(pubPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d Desired
	if err := json.Unmarshal(pb, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", pubPath, err)
	}
	if sb, err := a.readFile(secPath); err == nil {
		var sec secretSet
		if err := json.Unmarshal(sb, &sec); err != nil {
			return nil, fmt.Errorf("%s: %w", secPath, err)
		}
		joinSecrets(&d, sec)
	}
	return &d, nil
}
