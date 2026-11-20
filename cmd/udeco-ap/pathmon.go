// SPDX-License-Identifier: GPL-2.0-or-later

package main

// Path monitoring (fw3_caps 0x40, the controller's supportsPathMonitoring):
// the U6 Pro's upathmond, done in Go. The controller's system_cfg asks for
// ICMP probes of the gateway and the uplink device (pathmon.*); the agent
// probes them (internal/pathmon) and reports the inform's "pathmon" object.
// It only sends echo requests, so it runs in observe and takeover mode
// alike. docs/deco/features/pathmon.md.

import (
	"context"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/dtechterminal/udeco/internal/apstate"
	"github.com/dtechterminal/udeco/internal/pathmon"
	"github.com/dtechterminal/udeco/internal/translate"
)

// pathmonState is the agent's path monitor (loop goroutine fields).
type pathmonState struct {
	m     *pathmon.Monitor
	key   string // the system_cfg (cfgversion/N) last read
	notes string // its notes, logged when they change
	on    bool
}

// startPathmon starts the probing goroutine; it idles until system_cfg
// turns path monitoring on.
func (a *agent) startPathmon(ctx context.Context) {
	p := a.o.pmProber
	if p == nil {
		p = &pathmon.ICMP{}
	}
	a.pm = &pathmonState{m: pathmon.New(p, a.o.now)}
	a.bg.Add(1)
	go func() { defer a.bg.Done(); a.pm.m.Run(ctx) }()
}

// pathmonFields follows the saved system_cfg and the reading s (gateway,
// uplink neighbour) and adds the "pathmon" object to the inform fields f
// while monitoring is on. Loop goroutine.
func (a *agent) pathmonFields(f map[string]any, s *apstate.Snapshot) {
	pm := a.pm
	if pm == nil {
		return
	}
	key := strconv.FormatBool(a.x.S.Adopted) + "/" + a.x.WantedCfgVersion() + "/" + strconv.Itoa(a.x.S.SystemCfgN)
	if key != pm.key {
		pm.key = key
		var c *pathmon.Config
		var notes []string
		if a.x.S.Adopted {
			b, _ := os.ReadFile(a.sysCfgPath)
			c, notes = pathmon.FromCfg(translate.ParseCfg(string(b)))
		}
		pm.m.SetConfig(c)
		if n := strings.Join(notes, "; "); n != pm.notes {
			pm.notes = n
			if n != "" {
				a.logf("pathmon: %s", n)
			}
		}
		if on := c != nil; on != pm.on {
			pm.on = on
			if on {
				var t []string
				for _, x := range c.Targets {
					t = append(t, strings.TrimSuffix(x.Type+" "+x.Addr, " "))
				}
				a.logf("pathmon: on (every %s, timeout %s, %d-byte echoes) to %s", c.Interval, c.Timeout, c.Size, strings.Join(t, ", "))
			} else {
				a.logf("pathmon: off")
			}
		}
	}
	pm.m.SetAddrs(s.Gateway, a.uplinkMgmtIPv4())
	if r := pm.m.Report(); r != nil {
		f["pathmon"] = r
	}
}

// uplinkMgmtIPv4 is the "uplink" target: the first IPv4 management address
// of an LLDP neighbour heard on the uplink port ("" = none heard). On the
// U6 Pro the uplink target resolves to its LLDP neighbour's management
// address (docs/reference/u6pro/mca-dump.json: lldp_table mgmt_ips[0] =
// pathmon uplink resolved = 192.168.1.1).
func (a *agent) uplinkMgmtIPv4() string {
	if a.lldp == nil || a.topo == nil || a.topo.uplink == "" {
		return ""
	}
	for _, n := range a.lldp.Neighbors(a.topo.uplink) {
		for _, ip := range n.MgmtIPs {
			if v4 := net.ParseIP(ip).To4(); v4 != nil && !v4.IsUnspecified() {
				return v4.String()
			}
		}
	}
	return ""
}
