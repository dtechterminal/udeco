// SPDX-License-Identifier: GPL-2.0-or-later

package main

// mDNS service bridge (the controller's fw2_caps 0x10000000,
// supportsMdnsSdBridge; docs/deco/features/mdns-bridge.md).
//
// With the bit claimed, a WLAN whose mdns_proxy_mode is auto or custom makes
// the controller send the mdns_sd section (proxies between VLAN bridges,
// per-VAP service filters). internal/mdnsbr turns it into a plan for this
// unit and runs it: AF_PACKET taps and sends on the bridges' ports, ebtables
// interception of the vifs whose own-VLAN filter restricts something.
//
// Takeover with apply only: the vifs are the agent's, and the bridge sends
// frames. A drop to observe mode, R4 memory shedding or an empty plan stops
// it and undoes the interception. At the first tick the agent removes an
// interception a previous run left behind (crash, SIGKILL) in either mode:
// that only removes the agent's own chain. A marker in the run dir (ramfs,
// gone at reboot like the ebtables rules) is written before the bridge
// may intercept and removed once it has stopped cleanly, so a unit that
// never ran the bridge sees no ebtables command at all (observe mode runs
// none).

import (
	"context"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/mdnsbr"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
	"github.com/antoniocosta/unifi-openwrt/internal/unit"
)

type mdnsState struct {
	open    mdnsbr.Opener // nil = mdnsbr.Open (AF_PACKET)
	svc     *mdnsbr.Service
	key     string // the system_cfg the config was read from
	cfg     mdnsbr.Config
	notes   string // last logged notes
	err     string // last logged update error
	cleaned bool   // leftovers of an earlier run removed
}

// mdnsReconcile runs the bridge the saved system_cfg asks for. Loop
// goroutine only (agent.fields, after mcastMerge).
func (a *agent) mdnsReconcile(ctx context.Context, s *apstate.Snapshot, info apstate.CfgInfo) {
	if a.mdns == nil {
		a.mdns = &mdnsState{}
	}
	m := a.mdns
	if !m.cleaned && m.svc == nil {
		if _, err := os.Stat(a.mdnsMarker()); err != nil {
			m.cleaned = true // never intercepted since boot (or stopped cleanly)
		} else if err := mdnsbr.Cleanup(ctx, a.o.run); err != nil {
			a.logf("mdns bridge: removing an earlier run's interception: %v", err)
		} else {
			os.Remove(a.mdnsMarker())
			m.cleaned = true
		}
	}
	if !a.takeover.Load() || !a.cfg.Apply || !a.cfg.MdnsBridge || a.shed.Load() {
		a.mdnsStop(ctx)
		return
	}
	if a.wifiBusy.Load() {
		return // vifs are being rebuilt: the next tick sees the result
	}
	if m.key != a.infoKey {
		b, _ := os.ReadFile(a.sysCfgPath)
		var notes []string
		m.cfg, notes = mdnsbr.ParseConfig(translate.ParseCfg(string(b)))
		m.key = a.infoKey
		a.mdnsNotes(notes)
	}
	plan, notes := mdnsbr.BuildPlan(m.cfg, a.mdnsEnv(s, info))
	a.mdnsNotes(notes)
	if len(plan.Ports) == 0 {
		a.mdnsStop(ctx)
		return
	}
	if m.svc == nil {
		// the marker goes first: a crash after the first ebtables rule
		// must leave it for the next start's cleanup
		if err := a.writeMdnsMarker(); err != nil {
			a.logf("mdns bridge: not started: %v", err)
			return
		}
		m.svc = mdnsbr.NewService(ctx, mdnsbr.Options{Open: m.open, Run: a.o.run, Logf: a.logf})
		a.logf("mdns bridge: started")
	}
	err := m.svc.Update(ctx, plan)
	e := ""
	if err != nil {
		e = err.Error()
	}
	if e != m.err {
		if e != "" {
			a.logf("mdns bridge: %s (retried every inform)", e)
		}
		m.err = e
	}
}

// mdnsStop stops the bridge and gives the vifs their native mDNS back.
func (a *agent) mdnsStop(ctx context.Context) {
	m := a.mdns
	if m == nil || m.svc == nil {
		return
	}
	c := m.svc.Counters()
	if err := m.svc.Close(ctx); err != nil {
		a.logf("mdns bridge: stop: %v (the chain %s stays until the next start or a reboot)", err, mdnsbr.ChainName)
		m.cleaned = false // the marker stays: retried at the next tick
	} else {
		os.Remove(a.mdnsMarker())
	}
	m.svc, m.err = nil, ""
	a.logf("mdns bridge: stopped (frames in %d, out %d, filtered %d, limited %d, duplicate %d, own %d, bad %d)",
		c.In, c.Out, c.Filtered, c.Limited, c.Dup, c.Own, c.Bad)
}

// mdnsMarker is the run-dir file that says the bridge may have left an
// interception.
func (a *agent) mdnsMarker() string { return a.dev(filepath.Join(a.o.runDir, "mdns-bridge")) }

func (a *agent) writeMdnsMarker() error {
	p := a.mdnsMarker()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(mdnsbr.ChainName+"\n"), 0o600)
}

// mdnsShutdown is mdnsStop when the agent ends (bounded: ebtables only).
func (a *agent) mdnsShutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	a.mdnsStop(ctx)
}

func (a *agent) mdnsNotes(notes []string) {
	if len(notes) == 0 || a.mdns == nil {
		return
	}
	j := strings.Join(notes, "; ")
	if j != a.mdns.notes {
		a.mdns.notes = j
		a.logf("%s", j)
	}
}

// mdnsEnv reads what the planner needs: VAP names from the reading and the
// saved system_cfg, bridges and MACs from /sys.
func (a *agent) mdnsEnv(s *apstate.Snapshot, info apstate.CfgInfo) mdnsbr.Env {
	env := mdnsbr.Env{VAPs: s.IfnamesByDevname(info), Vifs: map[string]bool{}, Guest: map[string]bool{},
		Bridges: map[string][]string{}, Uplink: a.uplink}
	for _, r := range s.Radios {
		for _, v := range r.VAPs {
			if v.Iface != "" {
				env.Vifs[v.Iface] = true
			}
		}
	}
	for d, vif := range env.VAPs {
		if info.GuestVAP[d] {
			env.Guest[vif] = true
		}
	}
	sys := a.dev("/sys/class/net")
	ents, _ := os.ReadDir(sys)
	for _, e := range ents {
		n := e.Name()
		if b, err := os.ReadFile(path.Join(sys, n, "address")); err == nil {
			if mac, ok := parseMAC(strings.TrimSpace(string(b))); ok {
				env.MACs = append(env.MACs, mac)
			}
		}
		if n != unit.LANBridge && !strings.HasPrefix(n, unit.VLANBridgePrefix) {
			continue
		}
		ports, err := os.ReadDir(path.Join(sys, n, "brif"))
		if err != nil {
			continue
		}
		var ps []string
		for _, p := range ports {
			ps = append(ps, p.Name())
		}
		env.Bridges[n] = ps
	}
	return env
}

// parseMAC reads aa:bb:cc:dd:ee:ff (a unicast, non-zero address).
func parseMAC(s string) ([6]byte, bool) {
	var m [6]byte
	p := strings.Split(s, ":")
	if len(p) != 6 {
		return m, false
	}
	for i, x := range p {
		if len(x) != 2 {
			return m, false
		}
		var v byte
		for _, c := range strings.ToLower(x) {
			switch {
			case c >= '0' && c <= '9':
				v = v<<4 | byte(c-'0')
			case c >= 'a' && c <= 'f':
				v = v<<4 | byte(c-'a'+10)
			default:
				return m, false
			}
		}
		m[i] = v
	}
	return m, m != [6]byte{} && m[0]&1 == 0
}
