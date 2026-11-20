// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// LockChain is the login lock (docs/deco/features/login-lock.md): while
// the agent locks, it is the first rule of INPUT, IPv4 and IPv6, and drops
// new TCP connections to the unit's root login ports from every source but
// the loopback. Unlocked, neither the chain nor its jump exists, so a
// launcher clears a lock left behind with -D/-F/-X alone.
const LockChain = "UDECO-LOCK"

// ErrNoIptables: the unit has no iptables, so there is no lock.
var ErrNoIptables = errors.New("login lock: iptables not found")

// ErrLockUnchanged: locking failed before it had changed anything (a read
// that failed, say, with another process holding the xtables lock), so
// the unit's lock is exactly as it was: a complete lock stays complete,
// and none stays none. Set returns it wrapped and removes nothing.
var ErrLockUnchanged = errors.New("login lock: nothing changed")

// LockRules are the lock's rules for ports, in 'iptables -S' form after
// "-A UDECO-LOCK". Loopback and established sessions RETURN first (an
// open session is never cut, and RETURN, not ACCEPT, leaves them to the
// rest of INPUT: the Deco's UDECO-IN still drops TP-Link's ports for
// established sessions too); only then the DROPs, so a chain that fails
// half-way never drops what it should have let through. ESTABLISHED
// alone: an open session needs nothing else, and RELATED would let in a
// new connection to a login port that a conntrack helper (FTP's, say)
// expects.
func LockRules(ports []int) [][]string {
	rules := [][]string{
		{"-i", "lo", "-j", "RETURN"},
		{"-m", "conntrack", "--ctstate", "ESTABLISHED", "-j", "RETURN"},
	}
	for _, p := range ports {
		rules = append(rules, []string{"-p", "tcp", "-m", "tcp", "--dport", strconv.Itoa(p), "-j", "DROP"})
	}
	return rules
}

// LoginLock is the lock's firewall work on one unit. The zero Wait runs
// iptables without -w.
type LoginLock struct {
	Run Runner
	// IPv4, IPv6 are the iptables and ip6tables paths; one that is not
	// absolute is missing. No IPv4: no lock (ErrNoIptables). No IPv6: the
	// IPv4 lock alone.
	IPv4, IPv6 string
	Ports      []int // the login ports (Deco 22; Garage 23 and 22)
	Wait       bool  // pass -w (the xtables lock wait)
	DryRun     bool  // read, log the changes, change nothing
	Logf       func(string, ...any)
}

func (l LoginLock) fams() []string {
	var out []string
	for _, b := range []string{l.IPv4, l.IPv6} {
		if strings.HasPrefix(b, "/") {
			out = append(out, b)
		}
	}
	return out
}

func (l LoginLock) args(a ...string) []string {
	if l.Wait {
		return append([]string{"-w"}, a...)
	}
	return a
}

func (l LoginLock) logf(f string, a ...any) {
	if l.Logf != nil {
		l.Logf(f, a...)
	}
}

func (l LoginLock) read(ctx context.Context, bin string, a ...string) ([]byte, error) {
	return l.Run.Run(ctx, bin, l.args(a...)...)
}

func (l LoginLock) mutate(ctx context.Context, bin string, a ...string) error {
	return l.mutateRaw(ctx, bin, l.args(a...)...)
}

// mutateRaw runs a change as given (DryRun: logs it only).
func (l LoginLock) mutateRaw(ctx context.Context, bin string, args ...string) error {
	line := bin + " " + strings.Join(args, " ")
	if l.DryRun {
		l.logf("login lock: dry-run: %s", line)
		return nil
	}
	l.logf("login lock: run: %s", line)
	if _, err := l.Run.Run(ctx, bin, args...); err != nil {
		return fmt.Errorf("%s: %w", line, err)
	}
	return nil
}

// Set locks (on) or unlocks. Locking makes the chain hold exactly the
// rules and be jumped first from INPUT, in each family; it is idempotent
// and reports whether anything had to change (a lock lost and put back).
// It fails open: when anything goes wrong after a change was made, the
// lock is taken out of every family again and the error is returned, so a
// unit is never left half locked. An error before any change leaves the
// unit as it was (ErrLockUnchanged): tearing a complete lock down over a
// failed read would open it for nothing. Unlocking removes every jump,
// then the chain; nothing there costs two reads per family.
func (l LoginLock) Set(ctx context.Context, on bool) (bool, error) {
	if !strings.HasPrefix(l.IPv4, "/") {
		if on {
			return false, ErrNoIptables
		}
		return false, nil
	}
	if !on {
		return false, l.off(ctx)
	}
	rules := LockRules(l.Ports)
	changed := false
	for _, bin := range l.fams() {
		c, err := l.install(ctx, bin, rules)
		changed = changed || c
		if err != nil {
			if !changed {
				return false, fmt.Errorf("%w: %w", ErrLockUnchanged, err)
			}
			msg := "left open"
			if oerr := l.off(ctx); oerr != nil {
				msg = fmt.Sprintf("removing it again: %v", oerr)
			}
			return true, fmt.Errorf("login lock: %w (%s)", err, msg)
		}
	}
	return changed, nil
}

// install builds the chain in full, then jumps to it first from INPUT. It
// reports whether any change went through, on an error too (iptables
// commits each command whole or not at all).
func (l LoginLock) install(ctx context.Context, bin string, rules [][]string) (bool, error) {
	n := 0
	mut := func(ctx context.Context, bin string, args ...string) error {
		err := l.mutateRaw(ctx, bin, args...)
		if err == nil {
			n++
		}
		return err
	}
	out, err := l.read(ctx, bin, "-S", LockChain)
	if err != nil {
		if err := mut(ctx, bin, l.args("-N", LockChain)...); err != nil {
			return n > 0, err
		}
		out = nil
	}
	if out == nil || !sameRules(out, LockChain, rules) {
		if out != nil {
			if err := mut(ctx, bin, l.args("-F", LockChain)...); err != nil {
				return n > 0, err
			}
		}
		for _, r := range rules {
			if err := mut(ctx, bin, l.args(append([]string{"-A", LockChain}, r...)...)...); err != nil {
				return n > 0, err
			}
		}
	}
	_, err = jumpFirst(ctx, l.Run, mut, bin, l.args(), "INPUT", LockChain)
	return n > 0, err
}

// off removes every jump from INPUT to the chain, then the chain, in each
// family; it goes on to the next family after a failure.
func (l LoginLock) off(ctx context.Context) error {
	var errs []error
	for _, bin := range l.fams() {
		out, err := l.read(ctx, bin, "-S", "INPUT")
		if err != nil {
			errs = append(errs, fmt.Errorf("%s -S INPUT: %w", bin, err))
			continue
		}
		var ferr error
		for _, line := range strings.Split(string(out), "\n") {
			f := strings.Fields(line)
			if len(f) >= 2 && f[0] == "-A" && f[1] == "INPUT" && canonRule(f[2:]) == "-j "+LockChain {
				if ferr = l.mutate(ctx, bin, "-D", "INPUT", "-j", LockChain); ferr != nil {
					break
				}
			}
		}
		if ferr != nil {
			errs = append(errs, ferr)
			continue
		}
		if _, err := l.read(ctx, bin, "-S", LockChain); err != nil {
			continue // no chain
		}
		if err := l.mutate(ctx, bin, "-F", LockChain); err != nil {
			errs = append(errs, err)
			continue
		}
		errs = append(errs, l.mutate(ctx, bin, "-X", LockChain))
	}
	return errors.Join(errs...)
}

// LoginLock locks (on) or unlocks the Deco's root login port, dropbear's
// :22, for IPv4 and IPv6 (LoginLock.Set; serialised with the inbound
// fence, which keeps UDECO-IN right behind the lock). A lock that had to
// be put back is logged.
func (m *Manager) LoginLock(ctx context.Context, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loginLock(ctx, on)
}

// loginLock implements LoginLock; callers hold m.mu.
func (m *Manager) loginLock(ctx context.Context, on bool) error {
	l := LoginLock{Run: m.o.Run, IPv4: m.bin("iptables"), IPv6: m.bin("ip6tables"), Ports: []int{22},
		Wait: true, DryRun: m.o.DryRun, Logf: func(f string, a ...any) { m.o.Logf("decosys: "+f, a...) }}
	changed, err := l.Set(ctx, on)
	if on && err == nil && changed && m.locked {
		m.o.Logf("decosys: login lock: %s had to be put back", LockChain)
	}
	if !m.o.DryRun && !errors.Is(err, ErrLockUnchanged) {
		m.locked = on && err == nil
	}
	return err
}
