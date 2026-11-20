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
// the last controller reply that decoded with the device key (an
// encrypted reply, so the real controller sent it) is younger than
// login_lock_failopen_s (600 s). Anything else is OPEN.
//
// Who acts: the loop goroutine looks after every inform (cheap: it acts
// only when the decision changed, so the 10-minute fail-open lands within
// one inform interval); the worker's tick re-asserts a lock in place
// (rules can be lost); the agent's stop and the hand-back to TP-Link
// remove it. decosys/jiosys build the chain (UDECO-LOCK) and fail open:
// a lock that cannot be installed in full is taken out again. Each
// transition is an event (events.log): LOGIN LOCKED / LOGIN OPEN.

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/translate"
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
	lastReply time.Time             // the last controller reply that decoded (zero: none since start)
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
// section (refreshCreds, loop goroutine).
func (a *agent) lockFromCfg(adopted bool, sshd *translate.SSHDIntent) {
	a.login.mu.Lock()
	a.login.adopted, a.login.sshd = adopted, sshd
	a.login.mu.Unlock()
}

// lockAnswered records a controller reply that decoded with the device
// key (informOnce, loop goroutine).
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
		if e := err.Error(); e != st.errNoted {
			st.errNoted = e
			if on {
				a.logf("login lock: %v (the unit stays open; tried again at the next tick)", err)
			} else {
				a.logf("login lock: removing it (%s): %v (tried again at the next look)", why, err)
			}
		}
		// a failed lock takes itself out again (fail open)
		if on && st.locked {
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
