// SPDX-License-Identifier: GPL-2.0-or-later

package decosys

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// The Deco's lock: :22 (dropbear) only.
var lockRules22 = []string{
	"-A UDECO-LOCK -i lo -j RETURN",
	"-A UDECO-LOCK -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
	"-A UDECO-LOCK -p tcp -m tcp --dport 22 -j DROP",
}

// freshLock answers as a unit with no UDECO-LOCK chain yet.
func freshLock(r *fakeRun) {
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -S UDECO-LOCK", "", errExit1)
		r.on(b+" -w -S INPUT", tplinkInput, nil)
	}
}

func lockInstallCmds(bin string, rules []string) []string {
	want := []string{bin + " -w -S UDECO-LOCK", bin + " -w -N UDECO-LOCK"}
	want = append(want, prefixed(bin, rules)...)
	return append(want, bin+" -w -S INPUT", bin+" -w -I INPUT 1 -j UDECO-LOCK")
}

// Locked: the chain is built in full (loopback and established sessions
// RETURN before the :22 DROP), then jumped first from INPUT, IPv4 and IPv6.
func TestLoginLockInstall(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshLock(r)
	if err := ingressManager(u, r).LoginLock(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	calls := r.take()
	diff(t, calls, append(lockInstallCmds(ipt, lockRules22), lockInstallCmds(ip6t, lockRules22)...))
	// established before the drop, and the jump only once the chain is whole
	for _, bin := range []string{ipt, ip6t} {
		est := slices.Index(calls, bin+" -w -A UDECO-LOCK -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN")
		drop := slices.Index(calls, bin+" -w -A UDECO-LOCK -p tcp -m tcp --dport 22 -j DROP")
		jump := slices.Index(calls, bin+" -w -I INPUT 1 -j UDECO-LOCK")
		if est < 0 || drop < est || jump < drop {
			t.Errorf("%s: established %d, drop %d, jump %d", bin, est, drop, jump)
		}
	}
}

// LockRules is the rule list per port set: the Garage drops :23 and :22.
func TestLockRules(t *testing.T) {
	got := LockRules([]int{23, 22})
	var s []string
	for _, r := range got {
		s = append(s, strings.Join(r, " "))
	}
	want := []string{
		"-i lo -j RETURN",
		"-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		"-p tcp -m tcp --dport 23 -j DROP",
		"-p tcp -m tcp --dport 22 -j DROP",
	}
	diff(t, s, want)
}

// A lock in place costs two reads per family and changes nothing.
func TestLoginLockIdempotent(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	input := strings.Replace(tplinkInput, "-P INPUT DROP\n", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n-A INPUT -j UDECO-IN\n", 1)
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -S UDECO-LOCK", "-N UDECO-LOCK\n"+strings.Join(lockRules22, "\n")+"\n", nil)
		r.on(b+" -w -S INPUT", input, nil)
	}
	if err := ingressManager(u, r).LoginLock(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{ipt + " -w -S UDECO-LOCK", ipt + " -w -S INPUT", ip6t + " -w -S UDECO-LOCK", ip6t + " -w -S INPUT"})
}

// A lock whose jump slipped behind another rule is put first again; the
// stale jump is deleted by number after the new one is in.
func TestLoginLockJumpBackFirst(t *testing.T) {
	u := newUnit(t, "205")
	u.rm("usr/sbin/ip6tables")
	r := newFakeRun()
	r.on(ipt+" -w -S UDECO-LOCK", "-N UDECO-LOCK\n"+strings.Join(lockRules22, "\n")+"\n", nil)
	r.on(ipt+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-IN\n-A INPUT -j UDECO-LOCK\n", nil)
	if err := ingressManager(u, r).LoginLock(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{ipt + " -w -S UDECO-LOCK", ipt + " -w -S INPUT",
		ipt + " -w -I INPUT 1 -j UDECO-LOCK", ipt + " -w -D INPUT 3"})
}

// The inbound fence accepts the lock ahead of it: UDECO-LOCK first and
// UDECO-IN second is right for both, so neither moves the other every tick.
func TestIngressLeavesLockFirst(t *testing.T) {
	u := newUnit(t, "205")
	u.rm("usr/sbin/ip6tables")
	r := newFakeRun()
	v4 := append(slices.Clone(ingressHead),
		"-A UDECO-IN -s 192.168.0.0/24 -p tcp -m tcp --dport 22 -j ACCEPT",
		"-A UDECO-IN -s 192.168.0.1/32 -p tcp -m tcp --dport 2222 -j ACCEPT",
		"-A UDECO-IN -p tcp -m tcp --dport 2222 -j DROP")
	r.on(ipt+" -w -S UDECO-IN", "-N UDECO-IN\n"+strings.Join(v4, "\n")+"\n", nil)
	r.on(ipt+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n-A INPUT -j UDECO-IN\n-A INPUT -i lo -j ACCEPT\n", nil)
	m := ingressManager(u, r)
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{ipt + " -w -S UDECO-IN", ipt + " -w -S INPUT"})

	// no UDECO-IN yet behind the lock: inserted right after it
	r.set(ipt+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n-A INPUT -i lo -j ACCEPT\n", nil)
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{ipt + " -w -S UDECO-IN", ipt + " -w -S INPUT", ipt + " -w -I INPUT 2 -j UDECO-IN"})
}

// The lock leaves the inbound fence's rules exactly as they were.
func TestLoginLockLeavesIngressRules(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshIngress(r)
	m := ingressManager(u, r)
	if err := m.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	before := r.take()
	r2 := newFakeRun()
	freshIngress(r2)
	freshLock(r2)
	m2 := ingressManager(u, r2)
	if err := m2.LoginLock(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	r2.take()
	if err := m2.Ingress(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	diff(t, r2.take(), before)
}

// Any failure while locking leaves the unit open: what was added is taken
// out again, in both families, and the error is returned.
func TestLoginLockFailsOpen(t *testing.T) {
	for _, fail := range []string{
		ipt + " -w -A UDECO-LOCK -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN",
		ip6t + " -w -I INPUT 1 -j UDECO-LOCK",
		ip6t + " -w -N UDECO-LOCK",
	} {
		u := newUnit(t, "205")
		r := newFakeRun()
		freshLock(r)
		r.on(fail, "", errExit1)
		// the removal reads again: the v4 chain exists now, and its jump
		// too when v6 failed
		r.on(ipt+" -w -S UDECO-LOCK", "-N UDECO-LOCK\n", nil)
		if strings.HasPrefix(fail, ip6t) {
			r.on(ipt+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n", nil)
			r.on(ip6t+" -w -S UDECO-LOCK", "-N UDECO-LOCK\n", nil)
		}
		err := ingressManager(u, r).LoginLock(context.Background(), true)
		if err == nil {
			t.Fatalf("%s: want an error", fail)
		}
		calls := r.take()
		i := slices.Index(calls, fail)
		if i < 0 {
			t.Fatalf("%s not run: %v", fail, calls)
		}
		if strings.HasPrefix(fail, ipt+" ") {
			for _, c := range calls[:i] {
				if strings.Contains(c, "-j DROP") || strings.Contains(c, "-I INPUT") {
					t.Errorf("before the failed rule, ran %q", c)
				}
			}
		}
		after := calls[i+1:]
		for _, bin := range []string{ipt, ip6t} {
			if !slices.Contains(after, bin+" -w -S INPUT") || !slices.Contains(after, bin+" -w -S UDECO-LOCK") {
				t.Errorf("%s: %s lock not removed after the failure: %v", fail, bin, after)
			}
		}
		if strings.HasPrefix(fail, ip6t) && !slices.Contains(after, ipt+" -w -D INPUT -j UDECO-LOCK") {
			t.Errorf("%s: the IPv4 lock stayed while IPv6 failed: %v", fail, after)
		}
		for _, c := range after {
			if strings.Contains(c, " -A ") || strings.Contains(c, " -I ") {
				t.Errorf("%s: locked again during the removal: %q", fail, c)
			}
		}
	}
}

// No iptables: no lock (an error, nothing run); unlocking is a no-op.
func TestLoginLockNoIptables(t *testing.T) {
	u := newUnit(t, "205")
	u.rm("usr/sbin/iptables")
	r := newFakeRun()
	err := ingressManager(u, r).LoginLock(context.Background(), true)
	if !errors.Is(err, ErrNoIptables) {
		t.Errorf("err %v, want ErrNoIptables", err)
	}
	if err := ingressManager(u, r).LoginLock(context.Background(), false); err != nil {
		t.Errorf("unlock without iptables: %v", err)
	}
	diff(t, r.take(), nil)
}

// Unlocking removes every jump, then flushes and deletes the chain, per
// family; a family with nothing there costs two reads.
func TestLoginLockOff(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	r.on(ipt+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n-A INPUT -j UDECO-IN\n-A INPUT -j UDECO-LOCK\n", nil)
	r.on(ipt+" -w -S UDECO-LOCK", "-N UDECO-LOCK\n", nil)
	r.on(ip6t+" -w -S INPUT", tplinkInput, nil)
	r.on(ip6t+" -w -S UDECO-LOCK", "", errExit1)
	if err := ingressManager(u, r).LoginLock(context.Background(), false); err != nil {
		t.Fatal(err)
	}
	diff(t, r.take(), []string{
		ipt + " -w -S INPUT", ipt + " -w -D INPUT -j UDECO-LOCK", ipt + " -w -D INPUT -j UDECO-LOCK",
		ipt + " -w -S UDECO-LOCK", ipt + " -w -F UDECO-LOCK", ipt + " -w -X UDECO-LOCK",
		ip6t + " -w -S INPUT", ip6t + " -w -S UDECO-LOCK",
	})
}

// The hand-back to TP-Link removes the lock with the rest (Restore).
func TestRestoreRemovesLoginLock(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	for _, b := range []string{ipt, ip6t} {
		r.on(b+" -w -S INPUT", "-P INPUT DROP\n-A INPUT -j UDECO-LOCK\n", nil)
		r.on(b+" -w -S UDECO-LOCK", "-N UDECO-LOCK\n", nil)
		r.on(b+" -w -C OUTPUT -j UDECO-OUT", "", errExit1)
		r.on(b+" -w -S UDECO-OUT", "", errExit1)
		r.on(b+" -w -C INPUT -j UDECO-IN", "", errExit1)
		r.on(b+" -w -S UDECO-IN", "", errExit1)
	}
	m := newManager(u, r, false)
	m.Restore(context.Background())
	calls := r.take()
	for _, b := range []string{ipt, ip6t} {
		for _, c := range []string{" -w -D INPUT -j UDECO-LOCK", " -w -F UDECO-LOCK", " -w -X UDECO-LOCK"} {
			if !slices.Contains(calls, b+c) {
				t.Errorf("Restore did not run %s%s", b, c)
			}
		}
	}
}

// Dry-run reads but changes nothing.
func TestLoginLockDryRun(t *testing.T) {
	u := newUnit(t, "205")
	r := newFakeRun()
	freshLock(r)
	m := ingressManager(u, r)
	m.o.DryRun = true
	if err := m.LoginLock(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	for _, c := range r.take() {
		if !strings.Contains(c, " -S ") {
			t.Errorf("dry-run ran %q", c)
		}
	}
}

// canonRule treats the state match and the conntrack match alike, so a
// firmware that lists one as the other is not rewritten every tick.
func TestCanonStateMatch(t *testing.T) {
	a := canonRule(strings.Fields("-m state --state RELATED,ESTABLISHED -j RETURN"))
	b := canonRule(strings.Fields("-m conntrack --ctstate RELATED,ESTABLISHED -j RETURN"))
	if a != b {
		t.Errorf("%q != %q", a, b)
	}
}
