// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Login lock (docs/deco/features/login-lock.md): the unit's root logins
// (the Deco's dropbear on :22, the Garage's telnetd on :23 and :22) are
// closed to new connections while the UniFi controller is healthy and its
// Device SSH Authentication is off, and open again when either stops
// holding, so the owner can always get in when the controller is gone.
//
// LOCKED exactly when all hold: takeover with apply (and login_lock not
// false); adopted; the saved system_cfg's sshd section is there and lets
// no site login in from the LAN (translate.SSHDIntent.LANLogins false);
// the last controller reply that counts is younger than
// login_lock_failopen_s (its default and range: loginLockFailOpenKey in
// config.go). Anything else is OPEN.
//
// A reply counts (lockReply) only once the agent has handled it in full
// (decoded with the device key and accepted by device.Session.Handle: a
// random CBC frame can pass the padding check, never Handle) and only when
// its server_time_in_utc is later than every one counted before in this
// run: inform is plain HTTP, so someone on the path can send a sealed
// reply again. A replayed reply neither keeps the controller "answering"
// nor changes the lock's view of Device SSH (lockFromCfg keeps the view it
// had); its other effects are the agent's as before.
//
// Who acts: the loop goroutine looks after every inform (cheap: it acts
// only when the decision changed, so the fail-open lands within one
// inform interval); the worker's tick re-asserts a lock in place
// (rules can be lost); the agent's stop and the hand-back to TP-Link
// remove it. decosys/jiosys build the chain (UDECO-LOCK) and fail open:
// a lock that cannot be installed in full is taken out again. Each
// transition is an event (events.log): LOGIN LOCKED / LOGIN OPEN. The
// agent's stop releases the lock as soon as the inform loop ends
// (lockStop), and nothing locks again after that.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/dtechterminal/udeco/internal/decosys"
	"github.com/dtechterminal/udeco/internal/translate"
)

// loginLocker is the optional part of sysManager that locks
// (decosys.Manager, jiosys.Manager).
type loginLocker interface {
	LoginLock(ctx context.Context, on bool) error
}

// loginLockState is the lock's view (any goroutine, under mu).
type loginLockState struct {
	mu        sync.Mutex
	adopted   bool                  // from the last refreshCreds
	sshd      *translate.SSHDIntent // the saved system_cfg's sshd section (nil: none)
	lastReply time.Time             // the last controller reply that counted (zero: none since start)
	srvLast   int64                 // its server_time_in_utc (ms)
	stale     bool                  // the last reply handled did not count (a replay?)
	staleLog  bool                  // the ignored Device SSH change was logged
	stopped   bool                  // the agent's stop released it: nothing locks again
	init      bool                  // the first look was taken (it clears a crash's leftover)
	want      bool                  // the decision at the last look
	locked    bool                  // the lock is in (the last change succeeded)
	dirty     bool                  // the last change failed: the unit's state is not known
	errNoted  string                // the last error logged
}

// lockInputs is what the decision reads.
type lockInputs struct {
	takeover, adopted bool
	sshd              *translate.SSHDIntent
	lastReply, now    time.Time
	failOpen          time.Duration
}

// lockDecision is the owner's rule: locked, or open with the reason.
func lockDecision(in lockInputs) (bool, string) {
	switch {
	case !in.takeover:
		return false, "observe mode"
	case !in.adopted:
		return false, "not adopted"
	case in.sshd == nil:
		return false, "Device SSH setting not known"
	case in.sshd.LANLogins():
		return false, "Device SSH on"
	case in.lastReply.IsZero():
		return false, "no controller reply since the agent started"
	case in.now.Sub(in.lastReply) >= in.failOpen:
		return false, "controller silent " + shortDur(in.failOpen)
	}
	return true, "Device SSH off and controller answering"
}

// shortDur is 10m, 2m or 90s.
func shortDur(d time.Duration) string {
	if d%time.Minute == 0 {
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return fmt.Sprintf("%ds", d/time.Second)
}

// locker is the lock of a takeover-with-apply agent whose system manager
// has one; nil otherwise (the lock then never touches the unit).
func (a *agent) locker() loginLocker {
	if !a.cfg.loginLock() || a.sys == nil {
		return nil
	}
	l, _ := a.sys.(loginLocker)
	return l
}

// lockFromCfg takes the adoption state and the saved system_cfg's sshd
// section (refreshCreds, loop goroutine). A Device SSH change right after
// a reply that did not count (lockReply: not newer than the last one, so
// perhaps a replay) is not taken: the lock keeps the view it had until a
// reply that counts brings the change.
func (a *agent) lockFromCfg(adopted bool, sshd *translate.SSHDIntent) {
	st := &a.login
	st.mu.Lock()
	defer st.mu.Unlock()
	st.adopted = adopted
	if st.stale && !sameSSHD(st.sshd, sshd) {
		if !st.staleLog {
			st.staleLog = true
			a.logf("login lock: a Device SSH change from a reply that is not newer than the last one (server_time_in_utc; a replay?) is not taken")
		}
		return
	}
	st.sshd = sshd
}

// sameSSHD: both unknown, or both let site logins in from the LAN or not.
func sameSSHD(x, y *translate.SSHDIntent) bool {
	if x == nil || y == nil {
		return x == y
	}
	return x.LANLogins() == y.LANLogins()
}

// lockReply records a controller reply the agent handled (informOnce,
// loop goroutine, after device.Session.Handle accepted it). It counts as
// the controller answering only when its server_time_in_utc is later than
// that of every reply counted before; it reports whether it counted.
func (a *agent) lockReply(plain []byte, now time.Time) bool {
	ms, ok := serverTimeMS(plain)
	st := &a.login
	st.mu.Lock()
	defer st.mu.Unlock()
	if !ok || ms <= st.srvLast {
		st.stale = true
		return false
	}
	st.srvLast, st.lastReply, st.stale, st.staleLog = ms, now, false, false
	return true
}

// lockAnswered records a reply that counts at t.
func (a *agent) lockAnswered(t time.Time) {
	a.login.mu.Lock()
	a.login.lastReply = t
	a.login.mu.Unlock()
}

// lockEval decides and acts: force (the tick) re-asserts a lock in place;
// otherwise (the loop) only a changed decision installs it. A removal that
// failed is retried at every look.
func (a *agent) lockEval(ctx context.Context, force bool) {
	l := a.locker()
	if l == nil {
		return
	}
	st := &a.login
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.stopped {
		return
	}
	want, why := lockDecision(lockInputs{takeover: a.takeover.Load(), adopted: st.adopted, sshd: st.sshd,
		lastReply: st.lastReply, now: a.o.now(), failOpen: a.cfg.loginLockFailOpen()})
	first := !st.init
	change := first || want != st.want
	st.init, st.want = true, want
	switch {
	case want && (change || force):
		a.lockSet(ctx, l, true, why)
	case !want && (st.locked || st.dirty || first):
		a.lockSet(ctx, l, false, why)
	}
}

// lockSet locks or unlocks and records the transition; callers hold
// a.login.mu. Its own context: a SIGTERM must not cut a change in half.
func (a *agent) lockSet(ctx context.Context, l loginLocker, on bool, why string) {
	st := &a.login
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := l.LoginLock(cctx, on); err != nil {
		st.dirty = true
		kept := on && errors.Is(err, decosys.ErrLockUnchanged)
		if e := err.Error(); e != st.errNoted {
			st.errNoted = e
			switch {
			case kept:
				a.logf("login lock: %v (left as it was; tried again at the next tick)", err)
			case on:
				a.logf("login lock: %v (the unit stays open; tried again at the next tick)", err)
			default:
				a.logf("login lock: removing it (%s): %v (tried again at the next look)", why, err)
			}
		}
		// a failed lock takes itself out again (fail open); one that
		// failed before changing anything is as it was
		if on && st.locked && !kept {
			st.locked = false
			a.event("LOGIN OPEN: lock failed: " + err.Error())
		}
		return
	}
	st.dirty, st.errNoted = false, ""
	if on == st.locked {
		return
	}
	st.locked = on
	if on {
		a.event("LOGIN LOCKED: " + why)
	} else {
		a.event("LOGIN OPEN: " + why)
	}
}

// lockStop is the agent's stop: the lock goes as soon as the inform loop
// has ended (before the wait for background jobs, one of which may hang),
// and nothing locks again, not even a tick still running.
func (a *agent) lockStop() {
	a.login.mu.Lock()
	a.login.stopped = true
	a.login.mu.Unlock()
	a.lockRelease("agent stop")
}

// lockRelease removes the lock for good (the agent's stop, the hand-back
// to TP-Link), with its own short context: the run's is gone by then.
func (a *agent) lockRelease(why string) {
	l := a.locker()
	if l == nil {
		return
	}
	st := &a.login
	st.mu.Lock()
	defer st.mu.Unlock()
	st.init, st.want = true, false
	was := st.locked
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := l.LoginLock(ctx, false); err != nil {
		st.dirty = true
		a.logf("login lock: removing it (%s): %v (the launcher removes it before the next start; a reboot clears it)", why, err)
		return
	}
	st.locked, st.dirty, st.errNoted = false, false, ""
	if was {
		a.event("LOGIN OPEN: " + why)
	}
}
