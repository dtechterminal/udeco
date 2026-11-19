// SPDX-License-Identifier: GPL-2.0-or-later

package main

// SNMP (fw_caps 0x4000, supportsSNMPv3, and the site's v1/v2c community):
// the UAP's net-snmp snmpd, done in Go (internal/snmpagent). The controller's
// system_cfg snmp.* section turns a read-only agent on UDP :161 on or off:
// v1/v2c with the site community, v3 with the site's one USM user
// (authPriv only, MD5/DES as a UAP, or SHA/AES). It answers the LAN only,
// reads the unit and the inform state, and changes nothing, so it runs in
// observe and takeover mode alike. docs/deco/features/snmp.md.

import (
	"context"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
	"github.com/antoniocosta/unifi-openwrt/internal/snmpagent"
	"github.com/antoniocosta/unifi-openwrt/internal/translate"
)

// snmpState is the SNMP agent (loop goroutine fields).
type snmpState struct {
	key   string // the system_cfg (adopted/cfgversion/N) last read
	notes string // its notes, logged when they change
	desc  string // what runs, logged when it changes

	srv   *snmpagent.Server
	v3    bool // srv was built with an engine (boots) for v3
	stop  context.CancelFunc
	done  chan struct{}
	lan   netip.Prefix
	boots int64 // snmpEngineBoots of this run (0 = not taken yet)
	bErr  error // taking it failed: no v3 in this run
}

// snmpRetry: the wait before binding :161 is tried again.
const snmpRetry = 30 * time.Second

// snmpListen opens the agent's socket.
func (a *agent) snmpListen(ctx context.Context) (net.PacketConn, error) {
	if a.o.snmpListen != nil {
		return a.o.snmpListen(ctx)
	}
	var lc net.ListenConfig
	return lc.ListenPacket(ctx, "udp4", "0.0.0.0:161")
}

// snmpFollow starts, changes or stops the SNMP agent when the saved
// system_cfg changed, and hands it the reading s and its inform fields f.
// Loop goroutine; ctx is the agent's run context.
func (a *agent) snmpFollow(ctx context.Context, f map[string]any, s *apstate.Snapshot) {
	if a.snmp == nil {
		a.snmp = &snmpState{desc: "off"}
	}
	st := a.snmp
	key := strconv.FormatBool(a.x.S.Adopted) + "/" + a.x.WantedCfgVersion() + "/" + strconv.Itoa(a.x.S.SystemCfgN)
	if key != st.key {
		st.key = key
		var cfg *snmpagent.Config
		var notes []string
		if a.x.S.Adopted {
			b, _ := os.ReadFile(a.sysCfgPath)
			cfg, notes = snmpagent.FromCfg(translate.ParseCfg(string(b)))
		}
		cfg = a.snmpEngine(ctx, cfg, &notes)
		if n := strings.Join(notes, "; "); n != st.notes {
			st.notes = n
			if n != "" {
				a.logf("%s", n)
			}
		}
		a.snmpApply(ctx, cfg)
	}
	if st.srv == nil {
		return
	}
	v := snmpagent.FromFields(f)
	v.Model, v.Version = a.profile.Display, a.x.S.Version
	if v.Model == "" {
		v.Model = "U6-Lite"
	}
	if v.Hostname == "" {
		v.Hostname = s.Hostname
	}
	st.srv.SetView(v)
	// the LAN the unit's own address is on; none known: loopback only
	if p := snmpagent.PrefixFromIPMask(s.IP, s.Netmask); p != st.lan {
		st.lan = p
		if p.IsValid() {
			st.srv.SetAllow(snmpagent.LANAllow(p))
		} else {
			st.srv.SetAllow(nil)
		}
	}
}

// snmpEngine takes this run's snmpEngineBoots the first time v3 is wanted
// (RFC 3414: it must grow at every restart; saved in the session directory,
// one small write per agent start). Without it v3 stays off (fail closed).
func (a *agent) snmpEngine(ctx context.Context, cfg *snmpagent.Config, notes *[]string) *snmpagent.Config {
	st := a.snmp
	if cfg == nil || !cfg.V3 {
		return cfg
	}
	if st.boots == 0 && st.bErr == nil {
		st.boots, st.bErr = snmpagent.NextEngineBoots(snmpagent.BootsFile(a.sessDir))
	}
	if st.bErr != nil {
		*notes = append(*notes, "snmp: v3 off: engine boots: "+st.bErr.Error())
		c := *cfg
		c.V3, c.User, c.Password = false, "", ""
		if !c.V1V2c {
			return nil
		}
		return &c
	}
	return cfg
}

// snmpApply runs the agent for cfg (nil: stops it).
func (a *agent) snmpApply(ctx context.Context, cfg *snmpagent.Config) {
	st := a.snmp
	// a v3 setting on an agent built without an engine needs a new one
	if st.srv != nil && (cfg == nil || cfg.V3 && !st.v3) {
		st.stop()
		select {
		case <-st.done:
		case <-time.After(5 * time.Second):
		}
		st.srv, st.stop, st.done, st.lan = nil, nil, nil, netip.Prefix{}
	}
	if desc := cfg.String(); desc != st.desc {
		st.desc = desc
		a.logf("snmp: %s", desc)
	}
	if cfg == nil {
		return
	}
	if st.srv == nil {
		o := snmpagent.Options{Logf: a.logf}
		if cfg.V3 {
			o.EngineID, o.Boots = snmpagent.EngineIDFromMAC(a.x.Dev.MAC), st.boots
		}
		st.srv, st.v3 = snmpagent.New(o), cfg.V3
		sctx, cancel := context.WithCancel(ctx)
		st.stop, st.done = cancel, make(chan struct{})
		srv, done := st.srv, st.done
		a.bg.Add(1)
		go func() {
			defer a.bg.Done()
			defer close(done)
			a.serveSNMP(sctx, srv)
		}()
	}
	st.srv.SetConfig(cfg)
}

// serveSNMP binds the socket and serves until ctx ends; a failed bind (the
// port in use) is retried every snmpRetry, logged once.
func (a *agent) serveSNMP(ctx context.Context, srv *snmpagent.Server) {
	lastErr := ""
	for ctx.Err() == nil {
		pc, err := a.snmpListen(ctx)
		if err == nil {
			err = srv.Serve(ctx, pc)
		}
		if ctx.Err() != nil {
			return
		}
		if err != nil && err.Error() != lastErr {
			lastErr = err.Error()
			a.logf("snmp: %v (retrying every %s; further identical errors not logged)", err, snmpRetry)
		}
		select {
		case <-ctx.Done():
		case <-time.After(snmpRetry):
		}
	}
}
