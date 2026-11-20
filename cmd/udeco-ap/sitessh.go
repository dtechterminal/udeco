// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Site SSH logins on the agent's own SSH server (sshd_port), never
// on port 22, which is the owner's dropbear (docs/deco/agent-design.md
// "Site SSH logins"). Takeover only.
//
// Who may log in follows two things, and both must agree:
//   - the saved system_cfg (loop goroutine, refreshCreds): the controller's
//     Device SSH switch (sshd.status=enabled with a listener on a LAN
//     interface, translate.SSHDIntent.LANLogins) and its users.N. The
//     controller sends the users whether the switch is on or off; off only
//     moves a UniFi AP's sshd to lo, so off refuses every login here while
//     the accounts stay installed (users.go);
//   - the accounts the worker installed (users.go, marked in /etc/passwd)
//     with the same hash: a site user skipped because the unit already has
//     an account of that name never logs in, and a changed password only
//     works once installed.
//
// A system_cfg that switches logins off or removes a user takes effect at
// once (refreshCreds runs when it is saved, before any provisioning wait),
// and device.SSHAdopt.SetSite ends that user's open sessions. Sources: the
// mgmt_sources (IPv4) when set, else the unit's LAN; decosys opens the
// fence for them on sshd_port only while logins are on (IPv6 stays shut).

import (
	"context"
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/device"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"

	"golang.org/x/crypto/ssh"
)

type siteSSH struct {
	mu        sync.Mutex
	lan       string            // the unit's LAN CIDR (setLAN)
	cfgOn     bool              // the saved system_cfg switches logins on
	cfgUsers  map[string]string // its users.N, name -> hash
	cfgKeys   []ssh.PublicKey   // its Device SSH keys (sshd.auth.key.N)
	cfgNoPw   bool              // sshd.auth.passwd=disabled
	installed map[string]string // the marked accounts the worker installed, name -> hash
	logged    string            // the state last logged
}

// siteSSHOptions is SSHAdopt.Site: takeover configurations only. A session's
// PATH is agentPATH on both platforms (on jio-mtk too: not jioPATH).
func (a *agent) siteSSHOptions() *device.SiteOptions {
	if !a.cfg.Takeover {
		return nil
	}
	return &device.SiteOptions{Shell: a.o.siteShell, Home: a.dev("/root"), Path: agentPATH}
}

// siteFromCfg takes the saved system_cfg's switch and users (loop
// goroutine; in is empty when not adopted or no system_cfg is saved).
func (a *agent) siteFromCfg(adopted bool, in translate.Intent) {
	st := &a.site
	st.mu.Lock()
	st.cfgOn = adopted && in.SSHD.LANLogins()
	st.cfgKeys, st.cfgNoPw = nil, false
	if adopted && in.SSHD != nil {
		st.cfgNoPw = !in.SSHD.Passwords
		for _, k := range in.SSHD.Keys {
			pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(k.AuthorizedKey()))
			if err != nil {
				a.logf("site ssh: Device SSH key %q not understood: skipped", k.Comment)
				continue
			}
			st.cfgKeys = append(st.cfgKeys, pk)
		}
	}
	st.cfgUsers = map[string]string{}
	if adopted {
		for _, u := range in.Users {
			st.cfgUsers[u.Name] = u.Hash
		}
	}
	st.mu.Unlock()
	a.siteApply()
}

// siteInstalled records which of want the worker's last sync left
// installed as marked accounts (worker goroutine, after syncUsers).
func (a *agent) siteInstalled(want []translate.User) {
	marked := map[string]bool{}
	if b, err := os.ReadFile(a.dev("/etc/passwd")); err == nil {
		for _, l := range splitLines(b) {
			f := strings.Split(l, ":")
			if len(f) >= 7 && f[0] != "root" && f[2] == "0" && f[4] == userGECOS {
				marked[f[0]] = true
			}
		}
	}
	inst := map[string]string{}
	for _, u := range want {
		if marked[u.Name] {
			inst[u.Name] = u.Hash
		}
	}
	a.site.mu.Lock()
	a.site.installed = inst
	a.site.mu.Unlock()
	a.siteApply()
}

// siteLAN records the unit's LAN (loop goroutine, setLAN).
func (a *agent) siteLAN(cidr string) {
	a.site.mu.Lock()
	changed := a.site.lan != cidr
	a.site.lan = cidr
	a.site.mu.Unlock()
	if changed {
		a.siteApply()
	}
}

// siteSources are the IPv4 networks site logins may come from: the
// mgmt_sources when set (as for :22), else the LAN.
func (a *agent) siteSources(lan string) []*net.IPNet {
	var out []*net.IPNet
	add := func(s string) {
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s).To4(); ip != nil {
				out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)})
			}
			return
		}
		if _, n, err := net.ParseCIDR(s); err == nil && n.IP.To4() != nil {
			out = append(out, n)
		}
	}
	if len(a.cfg.MgmtSources) > 0 {
		for _, m := range a.cfg.MgmtSources {
			add(strings.TrimSpace(m))
		}
	} else if lan != "" {
		add(lan)
	}
	return out
}

// siteApply hands the current state to the SSH server and the fence, and
// logs a change (any goroutine).
func (a *agent) siteApply() {
	st := &a.site
	st.mu.Lock()
	takeover := a.takeover.Load()
	var users []device.SiteUser
	for name, h := range st.installed {
		if st.cfgUsers[name] == h {
			users = append(users, device.SiteUser{Name: name, Hash: h})
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })
	from := a.siteSources(st.lan)
	on := takeover && st.cfgOn && len(users) > 0 && len(from) > 0
	var desc string
	switch {
	case !a.cfg.Takeover:
		desc = "" // observe configuration: never on, nothing to say
	case !takeover:
		desc = "off (observe mode)"
	case !st.cfgOn:
		desc = "off (the controller's Device SSH Authentication is off: sshd disabled or on lo)"
	case len(users) == 0:
		desc = "off (no site user installed)"
	case len(from) == 0:
		desc = "off (the LAN is not known yet)"
	default:
		var names, nets []string
		for _, u := range users {
			names = append(names, u.Name)
		}
		for _, n := range from {
			nets = append(nets, n.String())
		}
		auth := "password"
		switch {
		case st.cfgNoPw:
			auth = fmt.Sprintf("%d key(s), no password", len(st.cfgKeys))
		case len(st.cfgKeys) > 0:
			auth = fmt.Sprintf("password or %d key(s)", len(st.cfgKeys))
		}
		desc = fmt.Sprintf("ON for %s (%s) from %s and the console", strings.Join(names, ", "), auth, strings.Join(nets, ", "))
	}
	changed := desc != st.logged
	st.logged = desc
	// still under st.mu: two goroutines never hand over in the wrong order
	if a.sa != nil {
		if on {
			a.sa.SetSite(device.SiteSSH{On: true, Users: users, From: from, Keys: st.cfgKeys, NoPasswords: st.cfgNoPw})
		} else {
			a.sa.SetSite(device.SiteSSH{})
		}
	}
	// the fence follows; in observe mode the fence is TP-Link's again
	// (Restore removed it), so it is only re-asserted in takeover
	fence := false
	if a.sys != nil {
		if f, ok := a.sys.(interface{ SetSiteSSH(bool) bool }); ok {
			fence = f.SetSiteSSH(on) && takeover
		}
	}
	st.mu.Unlock()

	if changed && desc != "" {
		a.logf("site ssh: logins on port %d %s", a.cfg.SSHDPort, desc)
	}
	if fence {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := a.sys.Ingress(ctx, true); err != nil {
			a.logf("site ssh: inbound fence: %v (re-tried every tick)", err)
		}
	}
}
