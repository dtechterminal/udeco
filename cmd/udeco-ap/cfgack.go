// SPDX-License-Identifier: GPL-2.0-or-later

package main

// When the controller's configuration counts as received (cfgversion), and
// who may SSH-adopt once the unit is adopted.
//
// cfgversion (device.Session.DeferCfgAck): the inform reports a new
// cfgversion only after its system_cfg is live: in takeover mode after the
// Wi-Fi apply succeeded (or the plan found it already live), in observe mode
// after the plan was logged. After a failed apply the previous cfgversion
// stays, so the controller provisions again. A system_cfg that failed is
// retried once more when the controller sends it again ("force provision",
// or its own resend); bcmwifi.ForgetFailed lets that retry through.

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"sync"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

type cfgState int

const (
	cfgNone    cfgState = iota
	cfgPending          // handed to the worker, not live yet
	cfgOK               // live (takeover) or logged (observe)
	cfgFailed           // the apply failed: not live
)

// cfgTrack is the outcome of the system_cfg handed last (loop and worker).
type cfgTrack struct {
	mu      sync.Mutex
	hash    [sha256.Size]byte
	state   cfgState
	retried [sha256.Size]byte // the failed system_cfg retried once already
}

func (t *cfgTrack) set(h [sha256.Size]byte, st cfgState) {
	t.mu.Lock()
	t.hash, t.state = h, st
	t.mu.Unlock()
}

func (t *cfgTrack) get(h [sha256.Size]byte) cfgState {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.hash != h {
		return cfgNone
	}
	return t.state
}

// newProvision captures a system_cfg for provisioning (loop goroutine).
func (a *agent) newProvision(why string, b []byte, h [sha256.Size]byte) provision {
	return provision{why: why, systemCfg: string(b), hash: fmt.Sprintf("%x", h[:6]), sum: h,
		cfgVersion: a.x.WantedCfgVersion(), blocked: append([]string{}, a.x.S.Blocked...)}
}

// cfgDone records a provision's outcome; a live one acknowledges its
// cfgversion.
func (a *agent) cfgDone(pv provision, ok bool) {
	if !ok {
		a.cfgs.set(pv.sum, cfgFailed)
		a.logf("cfgversion %s not acknowledged: the controller keeps provisioning until a system_cfg is live", pv.cfgVersion)
		return
	}
	a.cfgs.set(pv.sum, cfgOK)
	a.ackCfg(pv.cfgVersion)
}

// ackCfg hands a live cfgversion to the inform loop (any goroutine).
func (a *agent) ackCfg(cv string) {
	if cv == "" {
		return
	}
	select {
	case a.acks <- cv:
	default:
		a.logf("cfgversion %s: acknowledgement queue full", cv)
	}
	a.wakeLoop()
}

// drainAcks applies the acknowledgements before an inform (loop goroutine).
func (a *agent) drainAcks() {
	for {
		select {
		case cv := <-a.acks:
			if a.x.AckCfgVersion(cv) {
				a.logf("cfgversion %s acknowledged: its configuration is live", cv)
				if err := a.x.S.Save(a.statePath); err != nil {
					a.logf("saving state: %v", err)
				}
			}
		default:
			return
		}
	}
}

// onReply decides what a controller reply means for provisioning (loop
// goroutine): a new system_cfg is provisioned; a cfgversion for the
// system_cfg already live is acknowledged at once; a resent system_cfg that
// failed is retried once.
func (a *agent) onReply(o device.Outcome) {
	if !a.x.S.Adopted || o.Reset || (!o.SystemCfg && o.CfgVersion == "") {
		return
	}
	b, err := os.ReadFile(a.sysCfgPath)
	if err != nil || len(b) == 0 {
		return // nothing to apply yet: the controller sends system_cfg next
	}
	h := sha256.Sum256(b)
	if h != a.cfgHash {
		a.provisionIfNew("cfgversion " + a.x.WantedCfgVersion())
		return
	}
	switch a.cfgs.get(h) {
	case cfgOK:
		a.ackCfg(a.x.WantedCfgVersion())
	case cfgFailed:
		a.cfgs.mu.Lock()
		retry := o.SystemCfg && a.cfgs.retried != h && a.takeover.Load()
		if retry {
			a.cfgs.retried = h
		}
		a.cfgs.mu.Unlock()
		if !retry {
			return
		}
		pv := a.newProvision("resent by the controller (force provision): retried once", b, h)
		a.cfgs.set(h, cfgPending)
		a.logf("wifi: the controller sent system_cfg %s again after it failed: retrying it once", pv.hash)
		a.submit("retry "+pv.hash, func(ctx context.Context) {
			a.wifi.ForgetFailed()
			a.provision(ctx, pv)
		})
	}
}

// sshCreds is what ssh-adopt checks: before adoption any password (the
// console uses the factory login; the source is console_ip only); once
// adopted only a site device user (system_cfg users.N) with its password.
type sshCreds struct {
	adopted bool
	users   []translate.User
}

// refreshCreds re-reads the adoption state and the saved system_cfg's users
// (loop goroutine).
func (a *agent) refreshCreds() {
	c := &sshCreds{adopted: a.x.S.Adopted}
	var in translate.Intent
	if b, err := os.ReadFile(a.sysCfgPath); err == nil && c.adopted {
		in, _ = translate.IntentFromCfg(string(b))
		c.users = in.Users
	}
	a.creds.Store(c)
	a.siteFromCfg(c.adopted, in) // site SSH logins follow it at once (sitessh.go)
}

// sshAuth is SSHAdopt.Auth (SSH goroutines). Adopted and no site user
// known yet: refused (R12).
func (a *agent) sshAuth(user string, pw []byte) bool {
	c := a.creds.Load()
	if c == nil || !c.adopted {
		return true
	}
	for _, u := range c.users {
		if u.Name == user && device.VerifyCrypt(u.Hash, string(pw)) {
			return true
		}
	}
	return false
}
