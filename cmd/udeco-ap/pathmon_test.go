// SPDX-License-Identifier: GPL-2.0-or-later

package main

import (
	"context"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/dtechterminal/udeco/internal/lldp"
	"github.com/dtechterminal/udeco/internal/pathmon"
)

// pathmonCfg is the controller's pathmon section (Network 11.1.50, as sent
// to the U6 Pro).
const pathmonCfg = "pathmon.status=enabled\npathmon.interval=5\npathmon.timeout=1000\npathmon.ema_samples=60\npathmon.size=56\n" +
	"pathmon.target.1.type=gateway\npathmon.target.2.type=uplink\n"

// echoes answers every probe at 700 µs and records what was probed.
type echoes struct {
	mu   sync.Mutex
	dsts []string
}

func (e *echoes) Probe(_ context.Context, dst net.IP, size int, timeout time.Duration) (time.Duration, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if size != 56 || timeout != time.Second {
		return 0, pathmon.ErrTimeout
	}
	e.dsts = append(e.dsts, dst.String())
	return 700 * time.Microsecond, nil
}

func (e *echoes) probed() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return slices.Clone(e.dsts)
}

func pathmonRow(m map[string]any, typ string) map[string]any {
	pm, _ := m["pathmon"].(map[string]any)
	rows, _ := pm["targets"].([]any)
	for _, r := range rows {
		if rr, _ := r.(map[string]any); rr["type"] == typ {
			return rr
		}
	}
	return nil
}

// switchLLDP is an LLDPDU from a switch between the unit and the gateway
// (management address 192.168.0.2).
func switchLLDP(t *testing.T) []byte {
	t.Helper()
	mac, _ := net.ParseMAC("74:ac:b9:00:00:02")
	f, err := lldp.Encode(mac, lldp.Info{ChassisMAC: mac, PortID: "Port 5", TTL: 120, SysName: "USW",
		MgmtIPv4: net.ParseIP("192.168.0.2"), Caps: lldp.CapBridge})
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// Observe mode, adopted, system_cfg with the controller's pathmon section:
// the gateway (from the reading) and the uplink device (the LLDP neighbour
// on the uplink port) are probed, and the inform carries the U6 Pro's
// "pathmon" object; nothing on the unit is run. A system_cfg without the
// section turns it off and the object goes.
func TestPathmonInform(t *testing.T) {
	f := &fakeLLDP{in: map[string][][]byte{}, out: map[string][][]byte{}}
	e := &echoes{}
	h := newHarness(t, func(c *Config, o *options) {
		withLLDP(f)(c, o)
		o.pmProber = e
	})
	f.push("eth1", switchLLDP(t))
	h.ctl.queue(adoptReply, provisionReply(testCfg+pathmonCfg))
	h.start()
	eventually(t, "uplink probed", func() bool {
		r := pathmonRow(h.ctl.last(), "uplink")
		return r != nil && r["state"] == "reachable"
	})
	m := h.ctl.last()
	pm := m["pathmon"].(map[string]any)
	if num(pm["interval"]) != 5 || num(pm["ema_samples"]) != 60 {
		t.Errorf("pathmon header %v", pm)
	}
	gw, up := pathmonRow(m, "gateway"), pathmonRow(m, "uplink")
	for _, r := range []map[string]any{gw, up} {
		if r == nil || r["family"] != "ipv4" || r["state"] != "reachable" || num(r["latency_us"]) != 700 ||
			num(r["samples"]) < 1 || num(r["last_update_ts"]) < float64(time.Now().Add(-time.Minute).Unix()) {
			t.Errorf("row %v", r)
		}
	}
	if gw["resolved"] != "192.168.0.1" || up["resolved"] != "192.168.0.2" {
		t.Errorf("resolved gateway %v uplink %v", gw["resolved"], up["resolved"])
	}
	for _, d := range e.probed() {
		if d != "192.168.0.1" && d != "192.168.0.2" {
			t.Errorf("probed %s", d)
		}
	}
	if !strings.Contains(h.logs.all(), "pathmon: on (every 5s, timeout 1s, 56-byte echoes) to gateway, uplink") {
		t.Errorf("log lacks the pathmon start:\n%s", h.logs.all())
	}
	// the controller drops the section: monitoring stops, the object goes
	n := h.ctl.count()
	h.ctl.queue(fmt.Sprintf(`{"_type":"setparam","cfgversion":"00000000000000c2","mgmt_cfg":"cfgversion=00000000000000c2\n","system_cfg":%q}`, testCfg))
	eventually(t, "pathmon gone", func() bool { return h.ctl.count() > n+2 && h.ctl.last()["pathmon"] == nil })
	h.stop()
	for _, c := range h.rec.list() {
		t.Errorf("observe mode touched the unit: %s", c)
	}
	if !strings.Contains(h.logs.all(), "pathmon: off") {
		t.Error("log lacks pathmon: off")
	}
}

// Before adoption nothing is probed or reported, whatever is on disk.
func TestPathmonNotBeforeAdoption(t *testing.T) {
	e := &echoes{}
	h := newHarness(t, func(c *Config, o *options) { o.pmProber = e })
	h.start()
	eventually(t, "informs", func() bool { return h.ctl.count() > 5 })
	h.stop()
	if h.ctl.last()["pathmon"] != nil || len(e.probed()) != 0 {
		t.Errorf("pathmon before adoption: %v, probed %v", h.ctl.last()["pathmon"], e.probed())
	}
}
