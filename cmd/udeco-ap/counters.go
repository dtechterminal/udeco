// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/antoniocosta/unifi-openwrt/internal/apstate"
)

// Monotonic inform counters (apstate.Counters, agent-design §3.9). The state
// lives in the RAM run dir, so the totals survive an agent restart (crash,
// deploy, R4 exit) and a reboot clears them with the unit's own counters.
const (
	counterFile  = "counters.json"
	counterEvery = 30 * time.Second // persisted at most this often
)

func (a *agent) counterPath() string { return a.dev(filepath.Join(a.o.runDir, counterFile)) }

// loadCounters reads the run dir's state (an empty one when there is none
// or it is unreadable: the next reading is a baseline).
func (a *agent) loadCounters() {
	b, err := os.ReadFile(a.counterPath())
	c := apstate.LoadCounters(b)
	if err == nil && len(c.Src) > 0 {
		a.logf("inform counters: continuing from %s (%d sources, %d totals)", a.counterPath(), len(c.Src), len(c.Acc))
	}
	c.Ifindex = func(dev string) int64 { return int64(a.ifIndex(dev)) }
	a.ctr = c
}

// saveCounters writes the state when it changed and counterEvery has
// passed (force, or a change a restart would not repeat, Counters.Urgent:
// whenever it changed). The totals and the raw readings are written
// together, so a restart from an older file still adds exactly the traffic
// since then.
func (a *agent) saveCounters(now time.Time, force bool) {
	if a.ctr == nil || !a.ctr.Dirty() || !force && !a.ctr.Urgent() && now.Sub(a.ctrSaved) < counterEvery {
		return
	}
	b, err := a.ctr.Marshal()
	path := a.counterPath()
	tmp := path + ".tmp"
	if err == nil {
		err = os.MkdirAll(filepath.Dir(path), 0o700)
	}
	if err == nil {
		err = os.WriteFile(tmp, b, 0o600)
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		if a.ctrErr == "" {
			a.logf("inform counters: saving %s: %v (a restarted agent would start a new baseline)", path, err)
		}
		a.ctrErr = err.Error()
		return
	}
	a.ctrErr = ""
	a.ctr.ClearDirty()
	a.ctrSaved = now
}

// monoIfTable makes the if_table row's counters monotonic. The row is the
// uplink port renamed eth0 (topology.go), so a move of the cable between
// eth0 and eth1 would otherwise swap one port's counters for the other's.
func (a *agent) monoIfTable(f map[string]any) {
	rows, _ := f["if_table"].([]map[string]any)
	if a.ctr == nil || len(rows) == 0 {
		return
	}
	dev := a.topo.uplink
	if dev == "" {
		dev = "uplink" // the snapshot's own pick; no interface index
	}
	for _, row := range rows {
		name, _ := row["name"].(string)
		raw := map[string]int64{}
		for _, k := range apstate.IfFields {
			if v, ok := toInt64(row[k]); ok {
				raw[k] = v
			}
		}
		if len(raw) == 0 {
			continue
		}
		for k, v := range a.ctr.Netdev("if:"+name, dev, raw) {
			row[k] = v
		}
	}
}

func toInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case uint64:
		return int64(x), true
	case float64:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		return n, err == nil
	}
	return 0, false
}
